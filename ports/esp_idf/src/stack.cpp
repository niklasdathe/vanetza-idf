#include <vanetza_idf/stack.hpp>
#if VIDF_SECURITY
#include <vanetza_idf/security.hpp>
#endif
#include <vanetza/access/access_category.hpp>
#include <vanetza/btp/header.hpp>
#include <vanetza/btp/header_conversion.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/dcc/mapping.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/common/byte_view.hpp>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace vanetza_idf {
namespace gn = vanetza::geonet;
using namespace vanetza;

StackConfig::StackConfig() {
    // Explicit ITS-G5 subset. Defaults are upstream MIB, not R2 certification.
    mib.itsGnIfType = gn::InterfaceType::ITS_G5;
    mib.itsGnSnDecapResultHandling = gn::SecurityDecapHandling::Strict;
    mib.itsGnSecurity = true;
}

class Stack::Impl : public dcc::RequestInterface, public gn::TransportInterface {
public:
    StackConfig cfg;
    ManualRuntime& runtime;
    Access& access;
    vanetza::security::SecurityEntity* security;
    security::IdChangeService* id_change;
    gn::Router router;
    Receive receive;
    ReceiveGn receive_gn;
    Report report;
    bool position_valid = false;
    bool change_pending = false;
    std::optional<security::SubscriptionHandle> subscription;

    Impl(StackConfig c, ManualRuntime& rt, Access& al, vanetza::security::SecurityEntity* sec,
         security::IdChangeService* ids) :
        cfg(std::move(c)), runtime(rt), access(al), security(sec), id_change(ids), router(rt, cfg.mib) {
        router.set_access_interface(this);
        router.set_security_entity(sec);
        // MIB.itsGnLocalGnAddr is otherwise inert: Router::update_position only
        // touches timestamp/latitude/longitude/speed/heading, never the address,
        // and the router's own m_local_position_vector.gn_addr starts at
        // vanetza::geonet::Address()'s default (all-zero mid, not manually
        // configured) until this is called. Every GN packet's source position
        // vector carries that address, so leaving this out silently transmits
        // the wrong (default) station address regardless of what the caller
        // configured -- undetected by BTP's official ATS, which never checks
        // the source GN address, but not so for GeoNetworking's.
        router.set_address(cfg.mib.itsGnLocalGnAddr);
        router.set_transport_handler(gn::UpperProtocol::BTP_A, this);
        router.set_transport_handler(gn::UpperProtocol::BTP_B, this);
        router.set_transport_handler(gn::UpperProtocol::Unknown, this);
        // TS 103 836-4-1 V2.2.1 clause 10.2.1.4: the GN core of an anonymously addressed
        // station subscribes to the identifier-change service at startup (SN-IDCHANGE-SUBSCRIBE)
        // and derives its MID from the identifier of the security entity (TS 102 940 clause 6.5).
        if (cfg.mib.itsGnLocalAddrConfMethod == gn::AddrConfMethod::Anonymous && id_change) {
            subscription = id_change->subscribe(
                [this](security::IdChangeCommand command, const security::Identifier& id, const ByteBuffer&,
                       std::shared_ptr<security::IdChangeResponder> responder) { on_id_change(command, id, responder); });
            const auto current = id_change->current_identifier();
            if (current != security::Identifier {}) apply_identifier(current);
        }
    }

    ~Impl() override {
        // clause 10.2.1.4: unsubscribe when the router shuts down (SN-IDCHANGE-UNSUBSCRIBE)
        if (subscription && id_change) id_change->unsubscribe(*subscription);
    }

    // TS 102 940 V2.1.1 clause 6.5: the 48 least significant bits of the HashedId8 become the
    // MAC-layer / GN MID identifier. A source address must be individual (IEEE Std 802 clause
    // 8.2.2, I/G bit 0) and this one is not OUI-assigned (U/L bit 1).
    void apply_identifier(const security::Identifier& id) {
        MacAddress mid;
        std::copy(id.begin() + 2, id.end(), mid.octets.begin());
        mid.octets[0] = (mid.octets[0] & 0xfe) | 0x02;
        cfg.mib.itsGnLocalGnAddr.mid(mid);
        router.set_address(cfg.mib.itsGnLocalGnAddr);
    }

    // TS 102 723-8 V1.1.1 clauses 6.3.1.2 and 6.3.1.3: hook function of the GN core.
    void on_id_change(security::IdChangeCommand command, const security::Identifier& id,
                      const std::shared_ptr<security::IdChangeResponder>& responder) {
        switch (command) {
            case security::IdChangeCommand::PREPARE:
                change_pending = true;
                router.flush_forwarding_buffers(); // caches shall be flushed
                if (responder) responder->respond(true);
                break;
            case security::IdChangeCommand::COMMIT:
                apply_identifier(id);
                change_pending = false;
                if (responder) responder->respond(true);
                break;
            case security::IdChangeCommand::ABORT:
                change_pending = false;
                break;
            case security::IdChangeCommand::DEREG:
                change_pending = false;
                subscription.reset();
                break;
        }
    }

    void request(const dcc::DataRequest& req, std::unique_ptr<ChunkPacket> packet) override {
        auto out = cfg.radio_parameters;
        out.source = req.source;
        out.destination = req.destination;
        // DCC profile to IEEE 802.1D priority: upstream TS 102 687 mapping.
        // DCC enforcement belongs to the injected Access adapter; no fake CBR.
        out.priority = access::user_priority(dcc::map_profile_onto_ac(req.dcc_profile));
        const auto view = create_byte_view(*packet, OsiLayer::Network, max_osi_layer());
        out.data.assign(view.begin(), view.end());
        auto result = validate(out, cfg.maximum_gnpdu);
        if (result == Result::accepted) result = access.request(std::move(out));
        if (report) report(result);
    }

    void indicate(const gn::DataIndication& ind, std::unique_ptr<UpPacket> packet) override {
        if (ind.upper_protocol == gn::UpperProtocol::Unknown) {
            // GN-DATA.indication for a packet with no registered upper protocol
            // (Common Header next_header "Any"): the raw SDU, no BTP header to strip.
            if (!receive_gn) return;
            const auto view = create_byte_view(*packet, OsiLayer::Transport, max_osi_layer());
            receive_gn(GnIndication {ind, ByteBuffer(view.begin(), view.end())});
            return;
        }
        // IF-NF-002: validate length BEFORE parsing; upstream header parsing
        // alone does not reject a short BTP PDU. Never read an incomplete port.
        const auto view = create_byte_view(*packet, OsiLayer::Transport, max_osi_layer());
        if (view.size() < 4 || !receive) return;
        BtpIndication out {};
        out.type = ind.upper_protocol == gn::UpperProtocol::BTP_A ? BtpType::a : BtpType::b;
        out.destination_port = (std::uint16_t(view[0]) << 8) | view[1];
        const std::uint16_t second = (std::uint16_t(view[2]) << 8) | view[3];
        if (out.type == BtpType::a) out.source_port = second;
        else out.destination_port_info = second;
        out.gn = ind;
        // SN-DECAP.confirm -> NF-SAP: TS 102 723-8 V2.0.0 clause 5 /
        // V1.1.1 Table 27 and TS 103 836-5-1 Annex A.3.
        if (ind.certificate_id)
            out.certificate_id = ByteBuffer(ind.certificate_id->begin(), ind.certificate_id->end());
        out.data.assign(view.begin() + 4, view.end());
        receive(std::move(out));
    }
};

Stack::Stack(StackConfig config, ManualRuntime& runtime, Access& access,
             vanetza::security::SecurityEntity* security, security::IdChangeService* id_change) {
    if (config.mib.itsGnMaxSduSize < 4 || config.mib.itsGnMaxSduSize > 65535 ||
        config.maximum_gnpdu < config.mib.itsGnMaxSduSize ||
        config.mib.itsGnIfType != gn::InterfaceType::ITS_G5 ||
        config.mib.itsGnSnDecapResultHandling != gn::SecurityDecapHandling::Strict)
        throw std::invalid_argument("Invalid ITS-G5 stack configuration");
#if VIDF_SECURITY
    if (!id_change) {
        if (auto* own = dynamic_cast<security::SecurityEntity*>(security)) id_change = &own->id_change();
    }
#endif
    impl_ = std::make_unique<Impl>(std::move(config), runtime, access, security, id_change);
}
Stack::~Stack() = default;
const StackConfig& Stack::config() const { return impl_->cfg; }
security::IdChangeService* Stack::id_change() { return impl_->subscription ? impl_->id_change : nullptr; }
vanetza::security::SecurityEntity* Stack::security_entity() { return impl_->security; }
bool Stack::identity_change_pending() const { return impl_->change_pending; }
const gn::Address& Stack::address() const { return impl_->cfg.mib.itsGnLocalGnAddr; }
void Stack::on_receive(Receive receive) { impl_->receive = std::move(receive); }
void Stack::on_receive_gn(ReceiveGn receive) { impl_->receive_gn = std::move(receive); }
void Stack::on_access_result(Report report) { impl_->report = std::move(report); }

Result Stack::advance(Clock::time_point time) {
    if (time < impl_->runtime.now()) return Result::time_regression;
    impl_->runtime.trigger(time);
    return Result::accepted;
}
Result Stack::update_position(const PositionFix& fix) {
    if (!has_horizontal_position(fix) || fix.latitude.value() < -90 || fix.latitude.value() > 90 ||
        fix.longitude.value() < -180 || fix.longitude.value() > 180 ||
        fix.timestamp > impl_->runtime.now()) return Result::invalid_argument;
    impl_->router.update_position(fix);
    impl_->position_valid = true;
    return Result::accepted;
}
Result Stack::indicate(AlDataIndication ind) {
    if (ind.data.empty() || ind.data.size() > impl_->cfg.maximum_gnpdu) return Result::invalid_argument;
    try {
        auto packet = std::make_unique<UpPacket>(CohesivePacket(std::move(ind.data), OsiLayer::Network));
        impl_->router.indicate(std::move(packet), ind.source, ind.destination);
        return Result::accepted; // submitted for processing, NOT a receive verdict
    } catch (const std::bad_alloc&) { return Result::resource_limit; }
      catch (const std::exception&) { return Result::rejected; }
}
Result Stack::request(BtpRequest req) {
    // IF-NF-001: mutually exclusive BTP header variants and conditional fields.
    if ((req.type != BtpType::a && req.type != BtpType::b) ||
        (req.type == BtpType::a && (!req.source_port || req.destination_port_info)) ||
        (req.type == BtpType::b && req.source_port)) return Result::invalid_argument;
    if (req.data.size() > impl_->cfg.mib.itsGnMaxSduSize - 4u) return Result::resource_limit;
    if (req.communication_profile != gn::CommunicationProfile::ITS_G5 &&
        req.communication_profile != gn::CommunicationProfile::Unspecified) return Result::unsupported;
    if (req.security_profile && *req.security_profile != impl_->cfg.security_profile) return Result::unsupported;
    if (impl_->cfg.mib.itsGnSecurity && !impl_->security) return Result::security_unavailable;
    if (impl_->change_pending) return Result::identity_change_pending;
    if (!impl_->position_valid) return Result::rejected;
    if (req.maximum_hop_limit && (*req.maximum_hop_limit == 0 || *req.maximum_hop_limit > 255))
        return Result::invalid_argument;
    if (req.transport != gn::TransportType::SHB && req.transport != gn::TransportType::GBC)
        return Result::unsupported; // Upstream GUC, GAC, TSB are unimplemented: GAP-GN-001.
    if (req.transport == gn::TransportType::GBC && !boost::get<gn::Area>(&req.destination))
        return Result::invalid_argument;
    if (req.transport == gn::TransportType::SHB && !boost::get<std::nullptr_t>(&req.destination))
        return Result::invalid_argument;
    try {
        auto packet = std::make_unique<DownPacket>();
        // TS 103 836-5-1 clauses 7 and 8.2: both headers occupy four octets.
        if (req.type == BtpType::a) {
            btp::HeaderA header { host_cast(req.destination_port), host_cast(*req.source_port) };
            (*packet)[OsiLayer::Transport] = header;
        } else {
            btp::HeaderB header { host_cast(req.destination_port), host_cast(req.destination_port_info.value_or(0)) };
            (*packet)[OsiLayer::Transport] = header;
        }
        (*packet)[OsiLayer::Application] = std::move(req.data);
        auto apply = [&](gn::DataRequest& gn_req) {
            gn_req.upper_protocol = req.type == BtpType::a ? gn::UpperProtocol::BTP_A : gn::UpperProtocol::BTP_B;
            gn_req.communication_profile = req.communication_profile;
            gn_req.its_aid = req.its_aid;
            gn_req.permissions = std::move(req.permissions);
            gn_req.security_context = std::move(req.security_context);
            gn_req.traffic_class = req.traffic_class;
            if (req.maximum_lifetime) gn_req.maximum_lifetime = *req.maximum_lifetime;
            if (req.maximum_hop_limit) gn_req.max_hop_limit = *req.maximum_hop_limit;
            if (req.repetition) gn_req.repetition = *req.repetition;
        };
        gn::DataConfirm confirm;
        if (req.transport == gn::TransportType::SHB) {
            gn::ShbDataRequest gn_req(impl_->cfg.mib);
            apply(gn_req);
            confirm = impl_->router.request(gn_req, std::move(packet));
        } else {
            gn::GbcDataRequest gn_req(impl_->cfg.mib);
            apply(gn_req);
            gn_req.destination = boost::get<gn::Area>(req.destination);
            confirm = impl_->router.request(gn_req, std::move(packet));
        }
        return confirm.accepted() ? Result::accepted : Result::rejected;
    } catch (const std::bad_alloc&) { return Result::resource_limit; }
      catch (const std::exception&) { return Result::rejected; }
}
Result Stack::request(GnRequest req) {
    if (req.data.size() > impl_->cfg.mib.itsGnMaxSduSize) return Result::resource_limit;
    if (req.communication_profile != gn::CommunicationProfile::ITS_G5 &&
        req.communication_profile != gn::CommunicationProfile::Unspecified) return Result::unsupported;
    if (impl_->cfg.mib.itsGnSecurity && !impl_->security) return Result::security_unavailable;
    if (impl_->change_pending) return Result::identity_change_pending;
    if (!impl_->position_valid) return Result::rejected;
    if (req.maximum_hop_limit && (*req.maximum_hop_limit == 0 || *req.maximum_hop_limit > 255))
        return Result::invalid_argument;
    if (req.transport != gn::TransportType::SHB && req.transport != gn::TransportType::GBC)
        return Result::unsupported; // Upstream GUC, GAC, TSB are unimplemented: GAP-GN-001.
    if (req.transport == gn::TransportType::GBC && !boost::get<gn::Area>(&req.destination))
        return Result::invalid_argument;
    if (req.transport == gn::TransportType::SHB && !boost::get<std::nullptr_t>(&req.destination))
        return Result::invalid_argument;
    try {
        auto packet = std::make_unique<DownPacket>();
        (*packet)[OsiLayer::Application] = std::move(req.data);
        auto apply = [&](gn::DataRequest& gn_req) {
            gn_req.upper_protocol = gn::UpperProtocol::Unknown;
            gn_req.communication_profile = req.communication_profile;
            gn_req.its_aid = req.its_aid;
            gn_req.permissions = std::move(req.permissions);
            gn_req.security_context = std::move(req.security_context);
            gn_req.traffic_class = req.traffic_class;
            if (req.maximum_lifetime) gn_req.maximum_lifetime = *req.maximum_lifetime;
            if (req.maximum_hop_limit) gn_req.max_hop_limit = *req.maximum_hop_limit;
            if (req.repetition) gn_req.repetition = *req.repetition;
        };
        gn::DataConfirm confirm;
        if (req.transport == gn::TransportType::SHB) {
            gn::ShbDataRequest gn_req(impl_->cfg.mib);
            apply(gn_req);
            confirm = impl_->router.request(gn_req, std::move(packet));
        } else {
            gn::GbcDataRequest gn_req(impl_->cfg.mib);
            apply(gn_req);
            gn_req.destination = boost::get<gn::Area>(req.destination);
            confirm = impl_->router.request(gn_req, std::move(packet));
        }
        return confirm.accepted() ? Result::accepted : Result::rejected;
    } catch (const std::bad_alloc&) { return Result::resource_limit; }
      catch (const std::exception&) { return Result::rejected; }
}
}
