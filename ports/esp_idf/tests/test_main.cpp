#include <vanetza_idf/access.hpp>
#include <vanetza_idf/its_g5_frame.hpp>
#if VIDF_NETWORK
#include <vanetza_idf/stack.hpp>
#include <vanetza_idf/nf_sap.hpp>
#include <vanetza/security/sha.hpp>
#endif
#if VIDF_CAM || VIDF_DENM || VIDF_VAM
#include <vanetza_idf/facilities.hpp>
#endif
#if VIDF_HIL
#include <vanetza_idf/hil.hpp>
#endif
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <limits>

using namespace vanetza_idf;
namespace {
unsigned checks = 0;
void check(bool ok, const char* description) {
    ++checks;
    if (!ok) throw std::runtime_error(description);
}
struct Capture : Access {
    std::vector<AlDataRequest> packets;
    Result next = Result::accepted;
    Result request(AlDataRequest packet) override { packets.push_back(std::move(packet)); return next; }
};
void test_access() {
    Capture radio;
    AccessStack stack(radio, 32);
    AlDataRequest req;
    req.data = {1,2,3}; req.source = {2,0,0,0,0,1}; req.destination = {2,0,0,0,0,2};
    req.priority = 7; req.mcs = OfdmMcs::qam16_1_2; req.transmit_power_dbm = 12.5;
    req.channel_number = 176; req.bandwidth_mhz = 10; req.transceiver_id = 3;
    req.transceiver_mode = 0; req.datastream_id = 42;
    check(stack.request(req) == Result::accepted, "IN request accepted");
    auto& out = radio.packets.back();
    check(out.data == req.data && out.source == req.source && out.destination == req.destination,
          "IN addresses and payload preserved");
    check(out.priority == 7 && out.mcs == OfdmMcs::qam16_1_2 && out.transmit_power_dbm == 12.5 &&
          out.channel_number == 176 && out.transceiver_id == 3 && out.datastream_id == 42,
          "IN radio controls preserved");
    req.priority = 8;
    check(stack.request(req) == Result::invalid_argument, "Invalid priority rejected");
    req.priority = 1; req.data.resize(33);
    check(stack.request(req) == Result::invalid_argument, "Access MTU enforced");
    req.data.clear();
    check(stack.request(req) == Result::invalid_argument, "Empty access packet rejected");
    req.data = {1}; radio.next = Result::unsupported;
    check(stack.request(req) == Result::unsupported, "Backend failure preserved");
}
void test_its_g5_frame() {
    AlDataRequest request;
    request.source = {2,0,0,0,0,1}; request.destination = {255,255,255,255,255,255};
    request.priority = 6; request.data = {0x11, 0, 0, 1, 0x42};
    vanetza::ByteBuffer wire;
    check(its_g5::encode_frame(request, 0x123, wire) == Result::accepted, "QoS MPDU built");
    check(wire.size() == 39 && wire[0] == 0x88 && wire[24] == 6 &&
          wire[22] == 0x30 && wire[23] == 0x12 && wire[32] == 0x89 && wire[33] == 0x47,
          "QoS TID, sequence and LLC EtherType");
    AlDataIndication indication;
    check(its_g5::decode_frame(wire.data(), wire.size(), false, indication) == Result::accepted &&
          indication.data == request.data && indication.source == request.source &&
          indication.destination == request.destination, "MPDU round trip preserves AL_DATA");
    for (std::size_t length = 0; length < 34; ++length)
        check(its_g5::decode_frame(wire.data(), length, false, indication) == Result::invalid_argument,
              "Truncated MPDU rejected before header access");
    auto malformed = wire; malformed[1] = 1;
    check(its_g5::decode_frame(malformed.data(), malformed.size(), false, indication) == Result::unsupported,
          "To-DS frame rejected by OCB binding");
    malformed = wire; malformed[24] |= 0x80;
    check(its_g5::decode_frame(malformed.data(), malformed.size(), false, indication) == Result::unsupported,
          "A-MSDU cannot be interpreted as plain LLC");
    malformed = wire; malformed[33] = 0;
    check(its_g5::decode_frame(malformed.data(), malformed.size(), false, indication) == Result::unsupported,
          "Non-GeoNetworking EtherType rejected");
    wire.insert(wire.end(), 4, 0);
    check(its_g5::decode_frame(wire.data(), wire.size(), true, indication) == Result::accepted &&
          indication.data == request.data, "Explicit FCS removal");
    request.data.resize(its_g5::maximum_gnpdu + 1);
    check(its_g5::encode_frame(request, 0, wire) == Result::invalid_argument, "MAC MSDU limit enforced");
}
#if VIDF_NETWORK
void test_digests() {
    // FIPS 180-4 algorithms, standard "abc" known-answer vectors.
    const std::uint8_t input[] = {'a', 'b', 'c'};
    auto hex = [](const auto& bytes) {
        std::string result;
        const char* digits = "0123456789abcdef";
        for (auto b : bytes) { result += digits[b >> 4]; result += digits[b & 15]; }
        return result;
    };
    check(hex(vanetza::security::calculate_sha256_digest(input, sizeof(input))) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 known answer");
    check(hex(vanetza::security::calculate_sha384_digest(input, sizeof(input))) ==
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "SHA-384 known answer");
}
void test_network() {
    using namespace vanetza;
    ManualRuntime rt;
    Capture radio;
    StackConfig cfg;
    cfg.mib.itsGnSecurity = false; // explicitly unsecured laboratory profile
    cfg.mib.vanetzaDisableBeaconing = true;
    cfg.mib.itsGnLocalGnAddr.mid({2,0,0,0,0,1});
    Stack stack(cfg, rt, radio);
    PositionFix fix {};
    fix.latitude = 52.0 * units::degree; fix.longitude = 13.0 * units::degree;
    fix.speed = 0.0 * units::si::meters_per_second;
    fix.course = 0.0 * units::true_north_degrees;
    check(stack.update_position(fix) == Result::accepted, "Position accepted");
    BtpRequest req;
    req.destination_port = 2009; req.destination_port_info = 0x1234;
    req.data = {0x12,0x34,0x56};
    check(stack.request(req) == Result::accepted, "BTP-B SHB sent through router");
    check(radio.packets.size() == 1, "One SHB packet emitted");
    const auto wire = radio.packets.back();
    check(wire.data.size() == req.data.size() + 44, "GN SHB plus BTP header length");
    check(wire.data[40] == 0x07 && wire.data[41] == 0xd9 && wire.data[42] == 0x12 && wire.data[43] == 0x34,
          "BTP-B port and info use network byte order");
    // Different GN address avoids receiving own packet in the router.
    StackConfig receiver_cfg = cfg; receiver_cfg.mib.itsGnLocalGnAddr.mid({2,0,0,0,0,2});
    Capture receiver_radio; ManualRuntime receiver_rt;
    Stack receiver(receiver_cfg, receiver_rt, receiver_radio);
    receiver.update_position(fix);
    unsigned received = 0;
    receiver.on_receive([&](BtpIndication ind) {
        ++received;
        check(ind.destination_port == 2009 && ind.destination_port_info == 0x1234 &&
              !ind.source_port && ind.data == req.data, "BTP-B receive semantics");
    });
    AlDataIndication incoming;
    incoming.source = wire.source; incoming.destination = wire.destination; incoming.data = wire.data;
    check(receiver.indicate(incoming) == Result::accepted && received == 1, "SHB traverses both stacks");
    req.type = BtpType::a; req.source_port = 0xbeef; req.destination_port_info.reset();
    check(stack.request(req) == Result::accepted, "BTP-A SHB accepted");
    check(radio.packets.back().data[42] == 0xbe && radio.packets.back().data[43] == 0xef, "BTP-A source port preserved");
    req.source_port.reset();
    check(stack.request(req) == Result::invalid_argument, "BTP-A requires source port");
    req.type = BtpType::b; req.transport = geonet::TransportType::GUC;
    check(stack.request(req) == Result::unsupported, "Unsupported transport cannot silently become SHB");
    req.transport = geonet::TransportType::SHB; req.maximum_hop_limit = 0;
    check(stack.request(req) == Result::invalid_argument, "Hop limit boundary");
    req.maximum_hop_limit.reset(); req.data.resize(cfg.mib.itsGnMaxSduSize);
    check(stack.request(req) == Result::resource_limit, "BTP MTU includes header");
    check(stack.advance(Clock::time_point(Clock::duration(-1))) == Result::time_regression, "Time cannot move backwards");
    NF_SAP::BTP_DATA_request primitive;
    primitive.fl_sdu = {0x12, 0x34};
    primitive.destination_port = 2018;
    check(NF_SAP::BTP_DATA_request_submit(stack, primitive) == Result::invalid_argument,
          "NF-SAP length mismatch rejected");
    primitive.length = primitive.fl_sdu.size();
    primitive.gn_security_profile = NF_SAP::SecurityProfile::SECURED;
    check(NF_SAP::BTP_DATA_request_submit(stack, primitive) == Result::unsupported,
          "NF-SAP cannot silently downgrade secured request");
    primitive.gn_security_profile = NF_SAP::SecurityProfile::UNSECURED;
    check(NF_SAP::BTP_DATA_request_submit(stack, primitive) == Result::accepted,
          "Named NF-SAP request enters real router");
    check(radio.packets.back().data[40] == 0x07 && radio.packets.back().data[41] == 0xe2,
          "Named NF-SAP destination port preserved on wire");
    cfg.mib.itsGnSecurity = true; Capture secured_radio; Stack secured(cfg, rt, secured_radio);
    secured.update_position(fix); req.data = {1};
    check(secured.request(req) == Result::security_unavailable && secured_radio.packets.empty(), "Missing security fails closed");
}
#endif
#if VIDF_HIL
void test_hil() {
    using namespace hil;
    Frame f {Channel::upper, 0x12345678, {0,1,2,3}};
    auto wire = encode(f, 32);
    Decoder decoder(32);
    unsigned seen = 0;
    auto receive = [&](Frame got) {
        ++seen;
        check(got.sequence == f.sequence && got.payload == f.payload && got.channel == f.channel, "HIL frame integrity");
    };
    for (auto byte : wire) decoder.feed(&byte, 1, receive);
    check(seen == 1, "Bytewise HIL fragmentation");
    auto corrupt = wire; corrupt.back() ^= 1;
    decoder.feed(corrupt.data(), corrupt.size(), receive);
    check(seen == 1, "CRC failure never reaches tester");
    decoder.feed(wire.data(), wire.size(), receive);
    check(seen == 2, "Decoder resynchronizes");
    std::vector<std::uint8_t> junk(10000, 0x44);
    decoder.feed(junk.data(), junk.size(), receive);
    check(decoder.buffered() <= 3, "Decoder bounds garbage memory");
}
#endif
#if VIDF_CAM || VIDF_DENM || VIDF_VAM
void test_codecs() {
    using namespace facilities;
    for (auto k : {Kind::cam, Kind::denm, Kind::vam}) {
        check(validate_pdu(k, {}) == Result::invalid_argument, "Empty UPER rejected");
        check(validate_pdu(k, {0xff}) != Result::accepted, "Truncated UPER rejected");
    }
#if VIDF_CAM
    Cam cam;
    cam->header.protocolVersion = 2; cam->header.messageId = 2; cam->header.stationId = 42;
    auto& cp = cam->cam.camParameters;
    cp.basicContainer.stationType = 15;
    cp.highFrequencyContainer.present = Vanetza_ITS2_HighFrequencyContainer_PR_rsuContainerHighFrequency;
    auto& cam_pos = cp.basicContainer.referencePosition;
    cam_pos.latitude = 900000001; cam_pos.longitude = 1800000001;
    cam_pos.positionConfidenceEllipse.semiMajorAxisLength = 4095;
    cam_pos.positionConfidenceEllipse.semiMinorAxisLength = 4095;
    cam_pos.positionConfidenceEllipse.semiMajorAxisOrientation = 3601;
    cam_pos.altitude.altitudeValue = 800001; cam_pos.altitude.altitudeConfidence = 15;
    check(cam.validate(), "CAM constraints");
    check(validate_pdu(Kind::cam, cam.encode()) == Result::accepted, "CAM round trip");
    cam->header.protocolVersion = 1;
    check(validate_pdu(Kind::cam, cam.encode()) == Result::invalid_argument, "CAM protocol version enforced");
#endif
#if VIDF_DENM
    Denm denm;
    denm->header.protocolVersion = 2; denm->header.messageId = 1; denm->header.stationId = 42;
    auto& dm = denm->denm.management;
    dm.actionId.originatingStationId = 42;
    check(asn_long2INTEGER(&dm.detectionTime, 0) == 0 && asn_long2INTEGER(&dm.referenceTime, 0) == 0,
          "DENM timestamp allocation");
    dm.eventPosition.latitude = 900000001; dm.eventPosition.longitude = 1800000001;
    dm.eventPosition.positionConfidenceEllipse.semiMajorConfidence = 4095;
    dm.eventPosition.positionConfidenceEllipse.semiMinorConfidence = 4095;
    dm.eventPosition.positionConfidenceEllipse.semiMajorOrientation = 3601;
    dm.eventPosition.altitude.altitudeValue = 800001; dm.eventPosition.altitude.altitudeConfidence = 15;
    check(denm.validate(), "DENM constraints");
    check(validate_pdu(Kind::denm, denm.encode()) == Result::accepted, "DENM round trip");
#endif
#if VIDF_VAM
    Vam vam;
    check(descriptor(Kind::vam).port == 2018, "TS 103 248 Table 1 VAM destination port");
    vam->header.protocolVersion = 3; vam->header.messageId = 16; vam->header.stationId = 42;
    auto& hf = vam->vam.vamParameters.vruHighFrequencyContainer;
    hf.heading.value = 3601; hf.heading.confidence = 127;
    hf.speed.speedValue = 16383; hf.speed.speedConfidence = 127;
    hf.longitudinalAcceleration.longitudinalAccelerationValue = 161;
    hf.longitudinalAcceleration.longitudinalAccelerationConfidence = 102;
    auto& pos = vam->vam.vamParameters.basicContainer.referencePosition;
    pos.latitude = 900000001; pos.longitude = 1800000001;
    pos.positionConfidenceEllipse.semiMajorAxisLength = 4095;
    pos.positionConfidenceEllipse.semiMinorAxisLength = 4095;
    pos.positionConfidenceEllipse.semiMajorAxisOrientation = 3601;
    pos.altitude.altitudeValue = 800001; pos.altitude.altitudeConfidence = 15;
    check(vam.validate(), "VAM constraints");
    auto bytes = vam.encode();
    check(validate_pdu(Kind::vam, bytes) == Result::accepted, "VAM round trip");
    bytes.push_back(0);
    check(validate_pdu(Kind::vam, bytes) == Result::invalid_argument, "Trailing UPER bytes rejected");
#endif
}
#endif
}
int main() {
    try {
        test_access();
        test_its_g5_frame();
#if VIDF_NETWORK
        test_digests();
        test_network();
#endif
#if VIDF_HIL
        test_hil();
#endif
#if VIDF_CAM || VIDF_DENM || VIDF_VAM
        test_codecs();
#endif
        std::printf("PASS: %u checks (host/component tests, not ETSI ATS verdicts)\n", checks);
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
