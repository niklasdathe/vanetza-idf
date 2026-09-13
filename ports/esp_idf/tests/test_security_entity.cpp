// Security entity, TS 103 097 / TS 103 300-3 signing profiles and the
// TS 102 723-8 identifier-change service, on the isolated test trust domain.
#include "check.hpp"
#include "test_trust_domain.hpp"
#include <vanetza_idf/security.hpp>
#include <vanetza_idf/sf_sap.hpp>
#include <vanetza_idf/sn_sap.hpp>
#include <vanetza_idf/stack.hpp>
#include <vanetza_idf/facilities.hpp>
#include "test_backend.hpp"
#include <vanetza/common/byte_view.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <chrono>
#include <cstdio>
#include <memory>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza_idf;
using namespace std::chrono_literals;
using vidf_test::check;
namespace sec = vanetza_idf::security;

namespace {
struct Position : PositionProvider {
    PositionFix fix;
    Position() {
        fix.latitude = 52.5 * units::degree; fix.longitude = 13.4 * units::degree;
        fix.speed = 0.0 * units::si::meters_per_second; fix.course = 0.0 * units::true_north_degrees;
    }
    const PositionFix& position_fix() override { return fix; }
};
struct Radio : Access {
    std::vector<AlDataRequest> packets;
    Result request(AlDataRequest packet) override { packets.push_back(std::move(packet)); return Result::accepted; }
};

// 2026-09-13 ~10:00 TAI as seconds since the ITS epoch 2004-01-01 (Clock counts microseconds).
const Clock::time_point t0 = Clock::time_point(std::chrono::seconds(716292005));

// Secured message carried behind the 4-octet GN Basic Header (next header = secured packet).
v3::SecuredMessage secured_of(const AlDataRequest& frame) {
    check(frame.data.size() > 4 && (frame.data[0] & 0x0f) == 2, "basic header next_header = secured packet");
    v3::SecuredMessage message;
    check(message.decode(ByteBuffer(frame.data.begin() + 4, frame.data.end())), "EtsiTs103097Data decodes");
    return message;
}
bool has_certificate(const v3::SecuredMessage& m) { return v3::contains_certificate(m.signer_identifier()); }
bool has_digest(const v3::SecuredMessage& m) {
    return !has_certificate(m) && static_cast<bool>(v3::get_certificate_id(m.signer_identifier()));
}
bool has_generation_location(const v3::SecuredMessage& m) {
    return m->content->choice.signedData->tbsData->headerInfo.generationLocation != nullptr;
}

void verify_wire(Backend& backend, const v3::SecuredMessage& message, const v3::Certificate& at, Clock::time_point now,
                 ItsAid aid, const char* label) {
    check(message.protocol_version() == 3 && message.is_signed(), "EtsiTs103097Data-Signed, version 3");
    check(message.its_aid() == aid, "psid carries the ITS-AID of the message");
    check(message.generation_time() && *message.generation_time() == v2::convert_time64(now),
          "generationTime is the signing time");
    check(message.hash_id() == HashAlgorithm::SHA256, "hashId per IEEE 1609.2 5.3.3 for P-256");
    auto signature = message.signature();
    auto public_key = v3::get_public_key(*at.content());
    check(signature && public_key, "signature and AT verification key present");
    const auto digest = v3::calculate_message_hash(backend, HashAlgorithm::SHA256, message.signing_payload(), at);
    check(backend.verify_digest(*public_key, digest, *signature), label);
    auto id = v3::get_certificate_id(message.signer_identifier());
    check(id && *id == *at.calculate_digest(), "signer identifies the selected AT");
}

struct Station {
    ManualRuntime runtime {t0};
    Position position;
    vidf_test::TestBackend backend;
    vidf_test::TrustDomain domain {backend, t0};
    sec::CertificatePool pool {backend};
    sec::TrustConfiguration trust;
    std::unique_ptr<sec::SecurityEntity> entity;
    Radio radio;
    std::unique_ptr<Stack> stack;
    StackConfig cfg;

    Station() {
        check(trust.add_root(domain.root.certificate.encode()) == Result::accepted, "test root accepted as trust anchor");
        check(trust.add_authority(domain.aa.certificate.encode()) == Result::accepted, "test AA accepted as issuer");
        cfg.mib.vanetzaDisableBeaconing = true;
        cfg.mib.itsGnLocalGnAddr.mid({2, 0, 0, 0, 0, 1});
    }
    void start() {
        entity = std::make_unique<sec::SecurityEntity>(runtime, position, backend, pool, trust);
        stack = std::make_unique<Stack>(cfg, runtime, radio, entity.get());
        check(stack->update_position(position.fix) == Result::accepted, "position accepted");
    }
    Result send(ItsAid aid, ByteBuffer permissions = {}, ByteBuffer context = {}) {
        BtpRequest req;
        req.destination_port = 2018; req.destination_port_info = 0;
        req.its_aid = aid; req.permissions = std::move(permissions); req.security_context = std::move(context);
        req.data = {0x03, 0x10, 0x00, 0x00, 0x00, 0x2a};
        return stack->request(std::move(req));
    }
    v3::SecuredMessage last() { return secured_of(radio.packets.back()); }
    void advance(Clock::duration d) { check(stack->advance(runtime.now() + d) == Result::accepted, "time advances"); }
};

const vidf_test::TrustDomain::Permissions all_permissions {
    {aid::CA, {0x01, 0xff, 0xfc}}, {aid::DEN, {0x01, 0xff, 0xff, 0xff}}, {aid::VRU, {0x01}}, {aid::GN_MGMT, {}}};

void test_trust_domain_and_pool() {
    vidf_test::section("test_trust_domain_and_pool");
    Station s;
    check(s.domain.verify_chain_signature(s.domain.root.certificate, s.domain.root.certificate), "root self-signature verifies");
    check(s.domain.verify_chain_signature(s.domain.aa.certificate, s.domain.root.certificate), "AA signed by root");
    auto at = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    check(s.domain.verify_chain_signature(at.certificate, s.domain.aa.certificate), "AT signed by AA");
    check(!s.domain.verify_chain_signature(at.certificate, s.domain.root.certificate), "AT is not signed by root");
    check(at.certificate.is_canonical() && s.domain.aa.certificate.is_canonical(), "certificates in canonical form");
    // Provisioning through the COER + raw key path the station's own PKI would use.
    check(s.pool.add(at.certificate.encode(), at.key) == Result::accepted, "AT with matching key accepted");
    check(s.pool.add(at.certificate.encode(), at.key) == Result::invalid_argument, "duplicate AT rejected");
    auto other = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    check(s.pool.add(other.certificate.encode(), at.key) == Result::invalid_argument, "key of another AT rejected");
    PrivateKey brainpool = other.key; brainpool.type = KeyType::BrainpoolP256r1;
    check(s.pool.add(other.certificate.encode(), brainpool) == Result::invalid_argument, "key type mismatch rejected");
    check(s.pool.add(s.domain.aa.certificate.encode(), s.domain.aa.key) == Result::invalid_argument, "CA certificate is no AT");
    check(s.pool.add(ByteBuffer {0x80, 0x03}, at.key) == Result::invalid_argument, "garbage certificate rejected");
    check(s.pool.size() == 1 && s.pool.current()->digest == *at.certificate.calculate_digest(), "first AT is current");
    check(s.pool.next_valid(t0) == nullptr, "single AT has no successor");
    check(s.pool.add(other.certificate.encode(), other.key) == Result::accepted, "second AT accepted");
    check(s.pool.next_valid(t0)->digest == *other.certificate.calculate_digest(), "successor is the other AT");
    auto expired = s.domain.issue_ticket(all_permissions, t0 - 48h, 24);
    check(s.pool.add(expired.certificate.encode(), expired.key) == Result::accepted, "expired AT can be stored");
    check(s.pool.next_valid(t0)->digest == *other.certificate.calculate_digest(), "expired AT is never selected");
    check(s.pool.prune(t0) == 1 && s.pool.size() == 2, "prune removes the expired AT only");
    check(s.trust.add_root(s.domain.aa.certificate) == Result::invalid_argument, "AA is no root");
    check(s.trust.add_authority(s.domain.root.certificate) == Result::invalid_argument, "root is no subordinate CA");
}

void test_signing_profiles() {
    vidf_test::section("test_signing_profiles");
    Station s;
    auto at = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    check(s.pool.add(at.certificate, at.key) == Result::accepted, "AT provisioned");
    s.start();
    // Individual VAM: TS 103 300-3 clause 6.5.3 - certificate first, digest until one second elapsed.
    check(s.send(aid::VRU, {0x01}) == Result::accepted && s.radio.packets.size() == 1, "VAM signed and sent");
    auto m = s.last();
    verify_wire(s.backend, m, at.certificate, s.runtime.now(), aid::VRU, "VAM signature verifies with AT key");
    check(has_certificate(m), "first VAM attaches the certificate");
    check(!has_generation_location(m), "VAM carries no generationLocation (generic headerInfo)");
    s.advance(500ms); s.send(aid::VRU, {0x01});
    check(has_digest(s.last()), "VAM 500 ms later uses the digest");
    s.advance(499ms); s.send(aid::VRU, {0x01});
    check(has_digest(s.last()), "VAM 999 ms after the certificate still uses the digest");
    s.advance(1ms); s.send(aid::VRU, {0x01});
    check(has_certificate(s.last()), "VAM one second after the last certificate attaches it again");
    s.advance(100ms); s.entity->header_policy().report_new_cam_signer(); s.send(aid::VRU, {0x01});
    check(has_certificate(s.last()), "new CAM signer forces the certificate on the next individual VAM");
    s.advance(100ms); s.send(aid::VRU, {0x01});
    check(has_digest(s.last()), "flag consumed: digest again");
    // Cluster VAM: 500 ms cadence selected through context_information.
    s.advance(300ms); s.send(aid::VRU, {0x01}, sec::context::vam_cluster);
    check(has_digest(s.last()), "cluster VAM 400 ms after the certificate uses the digest");
    s.advance(100ms); s.send(aid::VRU, {0x01}, sec::context::vam_cluster);
    check(has_certificate(s.last()), "cluster VAM attaches the certificate after 500 ms");
    // CAM: TS 103 097 clause 7.1.1.
    s.advance(1s);
    s.send(aid::CA, {0x01, 0xff, 0xfc});
    m = s.last();
    verify_wire(s.backend, m, at.certificate, s.runtime.now(), aid::CA, "CAM signature verifies");
    check(has_certificate(m) && !has_generation_location(m), "first CAM: certificate, no generationLocation");
    for (int i = 1; i < 10; ++i) {
        s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
        check(has_digest(s.last()), "CAM within one second uses the digest");
    }
    s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
    check(has_certificate(s.last()), "CAM one second after the last certificate attaches it");
    s.advance(100ms); s.entity->header_policy().request_certificate(); s.send(aid::CA, {0x01, 0xff, 0xfc});
    check(has_certificate(s.last()), "certificate requested by the receiving side: attached at once");
    s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
    check(has_digest(s.last()), "request satisfied, timer restarted");
    // Inline P2PCD request for our own AT by a peer -> certificate; unknown digest -> inlineP2pcdRequest.
    s.entity->header_policy().enqueue_p2p_request(truncate(*at.certificate.calculate_digest()));
    s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
    check(has_certificate(s.last()), "peer asked for our AT digest: certificate attached");
    HashedId8 unknown {1, 2, 3, 4, 5, 6, 7, 8};
    s.entity->header_policy().request_unrecognized_certificate(unknown);
    s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
    // Read the ASN.1 field directly: upstream SecuredMessage::get_inline_p2pcd_request() widens the
    // 3-octet digest through an 8-octet conversion and truncates the wrong end (unused by upstream itself).
    m = s.last();
    const auto* p2pcd = m->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest;
    check(p2pcd && p2pcd->list.count == 1 && create_hashed_id3(*p2pcd->list.array[0]) == truncate(unknown),
          "inlineP2pcdRequest lists the unknown digest");
    // Peer asks for our AA certificate: requestedCertificate while we sign with the digest.
    s.entity->header_policy().enqueue_p2p_request(truncate(*s.domain.aa.certificate.calculate_digest()));
    s.advance(100ms); s.send(aid::CA, {0x01, 0xff, 0xfc});
    m = s.last();
    check(has_digest(m) && m->content->choice.signedData->tbsData->headerInfo.requestedCertificate != nullptr,
          "requestedCertificate carries the AA certificate");
    // DENM: clause 7.1.2.
    s.advance(100ms); s.send(aid::DEN, {0x01, 0xff, 0xff, 0xff});
    m = s.last();
    verify_wire(s.backend, m, at.certificate, s.runtime.now(), aid::DEN, "DENM signature verifies");
    check(has_certificate(m) && has_generation_location(m), "DENM: certificate and generationLocation");
    s.advance(100ms); s.send(aid::DEN, {0x01, 0xff, 0xff, 0xff});
    check(has_certificate(s.last()), "every DENM carries the certificate");
    // Generic profile (GN-MGMT beacon ITS-AID through the raw N-SAP).
    GnRequest gn; gn.its_aid = aid::GN_MGMT; gn.data = {0xaa};
    check(s.stack->request(gn) == Result::accepted, "GN-MGMT SDU signed");
    m = s.last();
    verify_wire(s.backend, m, at.certificate, s.runtime.now(), aid::GN_MGMT, "generic-profile signature verifies");
    check(has_certificate(m), "generic profile: certificate first");
    s.advance(100ms); s.stack->request(gn);
    check(has_digest(s.last()), "generic profile: digest within a second");
    check(s.entity->statistics().signed_messages == s.radio.packets.size(), "every packet on air was signed");
    // facilities::send fills ITS-AID and the VAM SSP version octet when the caller gives none.
    facilities::Vam vam;
    vam->header.protocolVersion = 3; vam->header.messageId = 16; vam->header.stationId = 42;
    auto& hf = vam->vam.vamParameters.vruHighFrequencyContainer;
    hf.heading.value = 3601; hf.heading.confidence = 127; hf.speed.speedValue = 16383; hf.speed.speedConfidence = 127;
    hf.longitudinalAcceleration.longitudinalAccelerationValue = 161;
    hf.longitudinalAcceleration.longitudinalAccelerationConfidence = 102;
    auto& pos = vam->vam.vamParameters.basicContainer.referencePosition;
    pos.latitude = 900000001; pos.longitude = 1800000001;
    pos.positionConfidenceEllipse.semiMajorAxisLength = 4095; pos.positionConfidenceEllipse.semiMinorAxisLength = 4095;
    pos.positionConfidenceEllipse.semiMajorAxisOrientation = 3601;
    pos.altitude.altitudeValue = 800001; pos.altitude.altitudeConfidence = 15;
    s.advance(1s);
    check(facilities::send(*s.stack, facilities::Kind::vam, vam.encode(), BtpRequest {}) == Result::accepted, "VAM via facilities");
    m = s.last();
    check(m.its_aid() == aid::VRU && has_certificate(m), "facilities::send selected ITS-AID 638");
    // SN-ENCAP over raw octets (another task, process or device would call this binding).
    SN_SAP::SN_ENCAP_request encap;
    encap.tbe_packet = {0x20, 0x50, 0x02, 0x01}; encap.tbe_packet_length = 4;
    encap.its_aid = aid::VRU; encap.permissions = {0x01};
    SN_SAP::SN_ENCAP_confirm confirm;
    check(SN_SAP::SN_ENCAP_request_submit(*s.entity, encap, confirm) == Result::accepted &&
          confirm.sec_packet_length == confirm.sec_packet.size() && confirm.sec_packet_length > 4,
          "SN-ENCAP.confirm carries a secured packet");
    v3::SecuredMessage raw;
    check(raw.decode(confirm.sec_packet) && raw.its_aid() == aid::VRU, "SN-ENCAP output is EtsiTs103097Data");
    encap.tbe_packet_length = 3;
    check(SN_SAP::SN_ENCAP_request_submit(*s.entity, encap, confirm) == Result::invalid_argument,
          "SN-ENCAP length mismatch rejected");
    encap.tbe_packet_length = 4; encap.target_id_list.push_back(unknown);
    check(SN_SAP::SN_ENCAP_request_submit(*s.entity, encap, confirm) == Result::unsupported,
          "encryption targets unsupported, not ignored");
}

void test_fail_closed() {
    vidf_test::section("test_fail_closed");
    // Each scenario owns its stations in a block: a Station (router, security entity,
    // trust domain) costs 25-45 kB of device heap and five of them do not fit.
    {
        Station s;
        s.start(); // empty pool
        check(s.send(aid::VRU, {0x01}) == Result::accepted, "router accepts the request");
        check(s.radio.packets.empty() && s.entity->statistics().refused_no_ticket == 1,
              "no AT: nothing is transmitted unsigned");
        auto cam_only = s.domain.issue_ticket({{aid::CA, {0x01, 0xff, 0xfc}}}, t0 - 1h, 24);
        check(s.pool.add(cam_only.certificate, cam_only.key) == Result::accepted, "CAM-only AT provisioned");
        s.send(aid::VRU, {0x01});
        check(s.radio.packets.empty() && s.entity->statistics().refused_permission == 1,
              "AT without VRU appPermissions is refused for a VAM (TS 103 097 7.2.1)");
        s.send(aid::CA, {0x01, 0xff, 0xfc});
        check(s.radio.packets.size() == 1, "the same AT signs a CAM");
    }
    {
        // Untrusted chain: an AT from a different, unknown AA is refused by the validator.
        vidf_test::section("test_fail_closed: unknown issuer");
        Station t;
        vidf_test::Credential stranger;
        {
            Station foreign;
            stranger = foreign.domain.issue_ticket(all_permissions, t0 - 1h, 24);
        }
        check(t.pool.add(stranger.certificate, stranger.key) == Result::accepted, "AT of unknown issuer can be stored");
        t.start();
        t.send(aid::VRU, {0x01});
        check(t.radio.packets.empty() && t.entity->statistics().refused_permission == 1,
              "AT whose chain is not anchored in the trust store is refused");
    }
    {
        // Expired AT.
        vidf_test::section("test_fail_closed: expired ticket");
        Station e;
        auto expired = e.domain.issue_ticket(all_permissions, t0 - 48h, 24);
        e.pool.add(expired.certificate, expired.key);
        e.start();
        e.send(aid::VRU, {0x01});
        check(e.radio.packets.empty(), "expired AT is refused");
    }
    {
        // SN-DECAP never reports success.
        vidf_test::section("test_fail_closed: SN-DECAP");
        Station r;
        auto at = r.domain.issue_ticket(all_permissions, t0 - 1h, 24);
        r.pool.add(at.certificate, at.key);
        r.start();
        r.send(aid::VRU, {0x01});
        auto message = r.last();
        vanetza::security::SecuredMessage variant {message};
        auto decap = r.entity->decapsulate_packet(DecapRequest {SecuredMessageView {variant}});
        check(!is_successful(decap.report) && decap.report == VerificationReport::Configuration_Problem &&
              decap.its_aid == aid::VRU, "SN-DECAP reports the missing verification, not success");
        // The same through the SN-SAP octet binding (TS 102 723-8 Tables 26/27).
        const auto& frame = r.radio.packets.back().data;
        SN_SAP::SN_DECAP_request request;
        request.sec_packet.assign(frame.begin() + 4, frame.end());
        request.sec_packet_length = request.sec_packet.size();
        SN_SAP::SN_DECAP_confirm confirm;
        check(SN_SAP::SN_DECAP_request_submit(*r.entity, request, confirm) == Result::accepted &&
              confirm.report == VerificationReport::Configuration_Problem && confirm.its_aid == aid::VRU &&
              confirm.plaintext_packet_length == confirm.plaintext_packet.size() && !confirm.plaintext_packet.empty(),
              "SN_DECAP_request_submit carries the report and the claimed ITS-AID");
        request.sec_packet_length += 1;
        check(SN_SAP::SN_DECAP_request_submit(*r.entity, request, confirm) == Result::invalid_argument,
              "SN-DECAP length mismatch is rejected");
        request.sec_packet = {0x03, 0x81, 0x00};
        request.sec_packet_length = 3;
        check(SN_SAP::SN_DECAP_request_submit(*r.entity, request, confirm) == Result::invalid_argument,
              "SN-DECAP of an undecodable packet is rejected");
    }
}

struct Subscriber {
    std::vector<sec::IdChangeCommand> commands;
    std::vector<sec::Identifier> ids;
    std::shared_ptr<sec::IdChangeResponder> held; // deferred response
    bool answer = true;
    bool defer = false;
    ByteBuffer seen_data;
    sec::IdChangeHook hook() {
        return [this](sec::IdChangeCommand c, const sec::Identifier& id, const ByteBuffer& data,
                      std::shared_ptr<sec::IdChangeResponder> responder) {
            commands.push_back(c); ids.push_back(id); seen_data = data;
            if (!responder) return;
            if (defer) held = responder; else responder->respond(answer);
        };
    }
};

void test_identifier_change() {
    vidf_test::section("test_identifier_change");
    Station s;
    auto at1 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    auto at2 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    s.pool.add(at1.certificate, at1.key);
    s.start();
    auto& svc = s.entity->id_change();
    check(svc.trigger() == Result::rejected, "single AT: no identifier to change to");
    s.pool.add(at2.certificate, at2.key);
    const auto id1 = *at1.certificate.calculate_digest();
    const auto id2 = *at2.certificate.calculate_digest();
    check(svc.current_identifier() == id1, "current identifier is the HashedId8 of the current AT");
    Subscriber local, remote;
    remote.defer = true;
    auto h1 = SN_SAP::SN_IDCHANGE_SUBSCRIBE_request_submit(svc, {local.hook(), {0x42}}).subscription;
    auto h2 = svc.subscribe(remote.hook());
    check(h1 != h2, "distinct subscription handles");
    // Happy path with one late (remote) response per phase: Figure 11.
    check(SN_SAP::SN_IDCHANGE_TRIGGER_request_submit(svc, {}) == Result::accepted, "trigger accepted");
    check(svc.change_pending() && local.commands.size() == 1 && local.commands[0] == sec::IdChangeCommand::PREPARE &&
          local.ids[0] == id2 && local.seen_data == ByteBuffer {0x42}, "PREPARE with the new id and subscriber_data");
    check(remote.held != nullptr && remote.commands.size() == 1, "remote subscriber still owes its PREPARE response");
    check(s.send(aid::VRU, {0x01}) == Result::accepted && s.radio.packets.empty() &&
          s.entity->statistics().refused_change_pending == 1, "no signing between PREPARE and COMMIT");
    check(svc.current_identifier() == id1, "identifier unchanged before COMMIT");
    auto respond = [&remote](bool rc) { auto r = remote.held; remote.held.reset(); r->respond(rc); };
    respond(true); // the COMMIT hook stores a new responder while this one is answered
    check(local.commands.size() == 2 && local.commands[1] == sec::IdChangeCommand::COMMIT &&
          remote.commands.size() == 2 && remote.commands[1] == sec::IdChangeCommand::COMMIT,
          "COMMIT after all PREPARE responses");
    check(svc.change_pending() && svc.current_identifier() == id2, "COMMIT phase: entity already uses the new AT");
    respond(true);
    check(!svc.change_pending() && s.entity->identity_manager().statistics().committed == 1, "change committed");
    s.send(aid::VRU, {0x01});
    auto m = s.last();
    verify_wire(s.backend, m, at2.certificate, s.runtime.now(), aid::VRU, "signed with the new AT after COMMIT");
    check(has_certificate(m), "new AT is attached right after the change");
    // Abort by a subscriber (Figure 13).
    local.answer = false;
    check(svc.trigger() == Result::accepted, "second trigger");
    check(local.commands.back() == sec::IdChangeCommand::ABORT && remote.commands.back() == sec::IdChangeCommand::ABORT,
          "false return_code aborts: every subscriber gets ABORT");
    check(!svc.change_pending() && svc.current_identifier() == id2, "aborted change keeps the identifier");
    remote.held.reset();
    local.answer = true;
    // Abort on timeout (Figure 12): the remote never answers.
    svc.trigger();
    check(svc.change_pending(), "waiting for the remote PREPARE response");
    s.advance(499ms);
    check(svc.change_pending(), "still waiting before the timeout");
    s.advance(1ms);
    check(!svc.change_pending() && local.commands.back() == sec::IdChangeCommand::ABORT &&
          s.entity->identity_manager().statistics().timed_out == 1, "timeout aborts the change");
    remote.held.reset();
    // Lock: a trigger waits for the automatic release (clause 6.3.2).
    remote.defer = false;
    auto lock = SN_SAP::SN_ID_LOCK_request_submit(svc, {2}).lock_handle;
    const auto before = local.commands.size();
    check(svc.trigger() == Result::accepted && !svc.change_pending() && local.commands.size() == before,
          "trigger while locked is queued, not executed");
    s.advance(1999ms);
    check(local.commands.size() == before, "lock still held");
    s.advance(1ms);
    check(!svc.change_pending() && s.entity->identity_manager().statistics().committed == 2 &&
          svc.current_identifier() == id1, "lock released automatically, queued change executed");
    check(svc.unlock(lock) == Result::invalid_argument, "released lock cannot be unlocked again");
    // Manual unlock executes a queued change at once.
    auto lock2 = svc.lock(200);
    svc.trigger();
    check(svc.current_identifier() == id1, "locked: no change");
    check(SN_SAP::SN_ID_UNLOCK_request_submit(svc, {lock2}) == Result::accepted && svc.current_identifier() == id2,
          "unlock runs the queued change");
    // Unsubscribe and DEREG on shutdown (Figures 14/15).
    check(svc.unsubscribe(h2) == Result::accepted && svc.unsubscribe(h2) == Result::invalid_argument, "unsubscribe once");
    const auto remote_count = remote.commands.size();
    svc.trigger();
    check(remote.commands.size() == remote_count && svc.current_identifier() == id1, "unsubscribed hook is not called");
    s.entity.reset();
    check(local.commands.back() == sec::IdChangeCommand::DEREG, "DEREG delivered when the entity shuts down");
    check(remote.commands.size() == remote_count, "no DEREG for an unsubscribed hook");
}

// TS 102 940 clause 6.5 / TS 103 836-4-1 clause 10.2.1.4: expected MID for an identifier.
MacAddress mid_of(const sec::Identifier& id) {
    MacAddress mid;
    std::copy(id.begin() + 2, id.end(), mid.octets.begin());
    mid.octets[0] = (mid.octets[0] & 0xfe) | 0x02;
    return mid;
}

void test_gn_core_identifier_change() {
    vidf_test::section("test_gn_core_identifier_change");
    Station s;
    auto at1 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    auto at2 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    s.pool.add(at1.certificate, at1.key);
    s.pool.add(at2.certificate, at2.key);
    const auto id1 = *at1.certificate.calculate_digest();
    const auto id2 = *at2.certificate.calculate_digest();
    s.cfg.mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Anonymous;
    s.start();
    auto& svc = s.entity->id_change();
    check(s.stack->id_change() == &svc, "anonymous GN core subscribed to the identifier-change service");
    check(s.stack->address().mid() == mid_of(id1), "initial MID = 48 LSB of the HashedId8, individual + local bits");
    check(mid_of(id1) != MacAddress {2, 0, 0, 0, 0, 1}, "configured MID replaced by the derived one");
    s.send(aid::VRU, {0x01});
    auto frame = s.radio.packets.back();
    check(frame.source == mid_of(id1), "link-layer source follows the derived MID");
    auto m = secured_of(frame);
    auto payload = m.payload();
    const auto& pdu = boost::get<CohesivePacket>(payload);
    // Payload = Common Header (8) + SHB header: SO PV starts with the 8-octet GN address, MID at +2.
    auto view = create_byte_view(pdu, OsiLayer::Network, max_osi_layer());
    const ByteBuffer so_pv(view.begin(), view.end());
    const MacAddress expected_mid = mid_of(id1);
    check(so_pv.size() >= 16 && std::equal(expected_mid.octets.begin(), expected_mid.octets.end(), so_pv.begin() + 10),
          "SO PV GN address MID carries the identifier");
    // Remote subscriber keeps PREPARE open: the GN core refuses requests meanwhile.
    Subscriber remote; remote.defer = true;
    svc.subscribe(remote.hook());
    check(svc.trigger() == Result::accepted && svc.change_pending() && s.stack->identity_change_pending(),
          "PREPARE delivered to the GN core");
    check(s.send(aid::VRU, {0x01}) == Result::identity_change_pending, "requests refused between PREPARE and COMMIT");
    GnRequest gn; gn.its_aid = aid::GN_MGMT; gn.data = {1};
    check(s.stack->request(gn) == Result::identity_change_pending, "raw GN requests refused as well");
    auto respond = [&remote](bool rc) { auto r = remote.held; remote.held.reset(); r->respond(rc); };
    respond(true); // PREPARE
    respond(true); // COMMIT
    check(!svc.change_pending() && !s.stack->identity_change_pending(), "change committed");
    check(s.stack->address().mid() == mid_of(id2), "COMMIT applied the new MID to the GN address");
    check(s.send(aid::VRU, {0x01}) == Result::accepted && s.radio.packets.back().source == mid_of(id2),
          "packets after COMMIT carry the new link-layer source");
    m = secured_of(s.radio.packets.back());
    auto id = v3::get_certificate_id(m.signer_identifier());
    check(id && *id == id2, "and are signed by the new AT");
    // Abort leaves the address untouched and lifts the pending state.
    remote.answer = false; remote.defer = false;
    svc.trigger();
    check(!s.stack->identity_change_pending() && s.stack->address().mid() == mid_of(id2), "ABORT keeps the address");
    // Shutdown unsubscribes the GN core: the entity no longer notifies it.
    s.stack.reset();
    remote.answer = true;
    check(svc.trigger() == Result::accepted && !svc.change_pending() && svc.current_identifier() == id1,
          "after the stack is gone the change completes with the remaining subscriber only");
    s.entity.reset(); // DEREG reaches `remote` while it is still alive (it outlives no entity otherwise)
    // Managed/auto address configuration does not subscribe.
    Station m2;
    auto at = m2.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    m2.pool.add(at.certificate, at.key);
    m2.start();
    check(m2.stack->id_change() == nullptr && m2.stack->address().mid() == MacAddress {2, 0, 0, 0, 0, 1},
          "managed address configuration keeps the configured MID");
}

// TS 103 300-3 V2.3.1 clause 5.3.5: the VRU basic service subscribes through the SF-SAP,
// stops generating VAMs on PREPARE and resumes after COMMIT with new identifiers.
void test_sf_facilities_hook() {
    vidf_test::section("test_sf_facilities_hook");
    Station s;
    auto at1 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    auto at2 = s.domain.issue_ticket(all_permissions, t0 - 1h, 24);
    s.pool.add(at1.certificate, at1.key);
    s.pool.add(at2.certificate, at2.key);
    s.cfg.mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Anonymous;
    s.start();
    auto& svc = s.entity->id_change();
    struct Vbs {
        bool generating = true;
        std::uint32_t station_id = 1;
        std::shared_ptr<sec::IdChangeResponder> pending; // answered from the facilities task later
        std::vector<sec::IdChangeCommand> seen;
    } vbs;
    auto confirm = SF_SAP::SF_IDCHANGE_SUBSCRIBE_request_submit(svc, {
        [&vbs](sec::IdChangeCommand command, const sec::Identifier& id, const ByteBuffer&,
               std::shared_ptr<sec::IdChangeResponder> responder) {
            vbs.seen.push_back(command);
            if (command == sec::IdChangeCommand::PREPARE) { vbs.generating = false; vbs.pending = responder; }
            if (command == sec::IdChangeCommand::COMMIT) {
                // StationId derived from the new identifier (TS 102 940 clause 6.5 least significant bits)
                vbs.station_id = (std::uint32_t(id[4]) << 24) | (std::uint32_t(id[5]) << 16) |
                                 (std::uint32_t(id[6]) << 8) | id[7];
                vbs.generating = true;
                vbs.pending = responder;
            }
        }, {}});
    check(confirm.subscription != 0, "SF-IDCHANGE-SUBSCRIBE.confirm returns a handle");
    const auto id2 = *at2.certificate.calculate_digest();
    check(SF_SAP::SF_IDCHANGE_TRIGGER_request_submit(svc, {}) == Result::accepted, "SF trigger accepted");
    check(!vbs.generating && vbs.pending && s.stack->identity_change_pending(),
          "facilities stopped generating on PREPARE, GN core prepared, commit waits for facilities");
    auto responder = vbs.pending; vbs.pending.reset();
    responder->respond(true); // late SF-IDCHANGE-EVENT.response(PREPARE)
    check(vbs.seen.back() == sec::IdChangeCommand::COMMIT && vbs.generating, "COMMIT resumed generation");
    responder = vbs.pending; vbs.pending.reset();
    responder->respond(true); // late response to COMMIT
    check(!svc.change_pending() && svc.current_identifier() == id2, "change completes after the late facilities response");
    check(vbs.station_id == ((std::uint32_t(id2[4]) << 24) | (std::uint32_t(id2[5]) << 16) | (std::uint32_t(id2[6]) << 8) | id2[7]),
          "facilities derived the StationId from the new identifier");
    check(s.stack->address().mid() == mid_of(id2), "GN core and facilities changed together");
    // Elevated-hazard lock from the facilities side (clause 5.3.5), released explicitly.
    auto lock = SF_SAP::SF_ID_LOCK_request_submit(svc, {30});
    check(SF_SAP::SF_IDCHANGE_TRIGGER_request_submit(svc, {}) == Result::accepted && !svc.change_pending() &&
          vbs.seen.back() == sec::IdChangeCommand::COMMIT, "locked: no PREPARE reaches the facilities");
    check(SF_SAP::SF_ID_UNLOCK_request_submit(svc, {lock.lock_handle}) == Result::accepted &&
          vbs.seen.back() == sec::IdChangeCommand::PREPARE, "unlock runs the deferred change");
    responder = vbs.pending; vbs.pending.reset(); responder->respond(true);
    responder = vbs.pending; vbs.pending.reset(); responder->respond(true);
    check(SF_SAP::SF_IDCHANGE_UNSUBSCRIBE_request_submit(svc, {confirm.subscription}) == Result::accepted, "SF unsubscribe");
}
} // namespace

void test_security_entity() {
    test_trust_domain_and_pool();
    test_signing_profiles();
    test_fail_closed();
    test_identifier_change();
    test_gn_core_identifier_change();
    test_sf_facilities_hook();
}
