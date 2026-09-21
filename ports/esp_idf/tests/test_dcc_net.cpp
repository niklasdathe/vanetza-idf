// Release-2 DCC_NET wiring (TS 103 836-4-2 V2.1.1 clauses 5, 6.3.3; SYS-DCC-003). The
// underlying algorithms (CbrAggregator's five-step CBR_G, DccMcoField's Table 3 bit layout,
// DccInformationSharing's periodic trigger) are upstream and already correct (verified against
// the standard text directly, not just the corrupted .txt cache -- see the thesis workbench
// notes); this file verifies that vanetza_idf::Stack actually wires them in: outgoing SHB
// packets carry a real DCC-MCO field instead of the default NullDccFieldGenerator's zero, and
// Stack::global_channel_busy_ratio() reflects DccInformationSharing's own state.
#include "check.hpp"
#include <vanetza_idf/stack.hpp>
#include <vanetza_idf/mn_sap.hpp>
#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/serialization_buffer.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/velocity.hpp>
#include <boost/iostreams/stream_buffer.hpp>
#include <chrono>
#include <cmath>
#include <memory>

using namespace vanetza;
using namespace vanetza_idf;
using vidf_test::check;

namespace {
bool near(double a, double b, double eps = 1e-9) { return std::fabs(a - b) < eps; }

struct Radio : Access {
    std::vector<AlDataRequest> packets;
    Result request(AlDataRequest packet) override { packets.push_back(std::move(packet)); return Result::accepted; }
};

// The GNPDU capture starts at the Basic Header; ShbHeader's own serialization begins right
// after Basic + Common (TS 103 836-4-1 V2.2.1 clauses 9.6-9.7), regardless of ShbHeader's
// internal byte layout -- so this needs no knowledge of DCC-MCO's exact offset within it.
geonet::ShbHeader deserialize_shb(const ByteBuffer& gnpdu) {
    using namespace geonet;
    const auto skip = BasicHeader::length_bytes + CommonHeader::length_bytes;
    check(gnpdu.size() > skip, "Captured GNPDU is at least Basic + Common + SHB headers long");
    byte_buffer_source source(gnpdu.begin() + skip, gnpdu.end());
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream);
    ShbHeader shb;
    deserialize(shb, ar);
    return shb;
}

// Stack has no move constructor (a deleted copy constructor plus a user-declared destructor
// suppress it), so a helper builds it on the heap rather than returning it by value.
std::unique_ptr<Stack> build_ready_stack(ManualRuntime& runtime, Access& access) {
    StackConfig cfg;
    cfg.mib.itsGnSecurity = false;
    cfg.mib.vanetzaDisableBeaconing = true;
    cfg.mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Managed;
    cfg.mib.itsGnLocalGnAddr.mid({2, 0, 0, 0, 0, 1});
    auto stack = std::make_unique<Stack>(cfg, runtime, access);
    // Must be checked here: applying time/position below jumps the runtime far forward in
    // one step, which fires DccInformationSharing's self-rescheduling trigger many times
    // over on the way -- checking after that point would no longer observe the "before the
    // first trigger" state at all.
    check(!stack->global_channel_busy_ratio().has_value(),
          "CBR_G is unavailable before DccInformationSharing's first 100 ms trigger");
    MN_SAP::CORE_MMT_response ready;
    ready.time = Clock::time_point(std::chrono::seconds(716292005));
    PositionFix fix;
    fix.timestamp = *ready.time;
    fix.latitude = 48.1 * units::degree; fix.longitude = 11.6 * units::degree;
    fix.speed = 1.5 * units::si::meters_per_second; fix.course = 90.0 * units::true_north_degrees;
    ready.local_position_vector = fix;
    check(MN_SAP::CORE_MMT_response_apply(*stack, ready) == Result::accepted, "test station has time and position");
    return stack;
}

BtpRequest shb_request() {
    BtpRequest req;
    req.destination_port = 2018;
    req.destination_port_info = 0;
    req.data = {1, 2, 3};
    return req;
}
} // namespace

void test_dcc_net() {
    vidf_test::section("test_dcc_net");

    // -- DCC-MCO round trip through a real ShbHeader (TS 103 836-4-2 Table 3 quantisation:
    // floor(cbr * 255), so 0.2 and 0.4 are chosen as exact multiples of 1/255).
    {
        geonet::ShbHeader shb1;
        geonet::DccMcoField mco;
        mco.local_cbr(dcc::ChannelLoad(0.2));
        mco.neighbour_cbr(dcc::ChannelLoad(0.4));
        mco.output_power(17);
        shb1.dcc = mco;
        ByteBuffer buffer;
        geonet::serialize_into_buffer(shb1, buffer);
        check(buffer.size() == geonet::ShbHeader::length_bytes, "ShbHeader serializes to its declared length");
        geonet::ShbHeader shb2;
        geonet::deserialize_from_buffer(shb2, buffer);
        auto mco2 = geonet::get_dcc_mco(shb2.dcc);
        check(static_cast<bool>(mco2), "DCC-MCO variant survives the round trip, not the legacy uint32_t reserved field");
        check(near(mco2->local_cbr().value(), 0.2) && near(mco2->neighbour_cbr().value(), 0.4) && mco2->output_power() == 17,
              "DCC-MCO field content survives serialize/deserialize exactly");
    }

    // -- Stack wiring: global CBR_G is unavailable before any DCC_NET aggregation cycle,
    // and outgoing SHB packets carry the fed local CBR/TX power, not a null/zero field.
    {
        ManualRuntime runtime;
        Radio radio;
        auto stack = build_ready_stack(runtime, radio);
        stack->report_local_channel_load(dcc::ChannelLoad(51.0 / 255.0)); // exact 1/255 multiple
        stack->report_tx_power(10);
        // report_local_channel_load only feeds DccInformationSharing's next scheduled 100 ms
        // trigger (clause 5.3's own cadence, independent of when this is called); it does not
        // synchronously update the aggregator generate_dcc_field() reads from.
        runtime.trigger(std::chrono::milliseconds(100));
        check(stack->request(shb_request()) == Result::accepted, "SHB transmission with DCC_NET wired in still succeeds");
        const auto shb = deserialize_shb(radio.packets.back().data);
        const auto mco = geonet::get_dcc_mco(shb.dcc);
        check(static_cast<bool>(mco), "Outgoing SHB carries a real DCC-MCO field, not NullDccFieldGenerator's reserved zero");
        check(near(mco->local_cbr().value(), 51.0 / 255.0) && mco->output_power() == 10,
              "Outgoing DCC-MCO reflects the fed local CBR and TX power");
    }
}
