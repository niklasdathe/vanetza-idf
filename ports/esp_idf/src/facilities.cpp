#include <vanetza_idf/facilities.hpp>
#include <vanetza/common/its_aid.hpp>
#include <utility>

namespace vanetza_idf::facilities {
Descriptor descriptor(Kind kind) {
    // TS 103 248 BTP well-known ports; CDD MessageId values. The service
    // protocolVersion comes from each service ASN.1 definition: CAM/DENM 2,
    // VAM 3 (TS 103 300-3 V2.3.1 ItsPduHeaderVam). Release != protocolVersion.
    switch (kind) {
        case Kind::cam: return {2001, 2, 2};
        case Kind::denm: return {2002, 1, 2};
        // TS 103 248 V2.4.1, Table 1: VA (VAM) is 2018; 2009 is CP (CPM).
        case Kind::vam: return {2018, 16, 3};
    }
    return {0, 0, 0};
}
template<class Message>
Result check(Kind kind, const vanetza::ByteBuffer& data) {
    Message message;
    if (!message.decode_exact(data) || !message.validate()) return Result::invalid_argument;
    const auto expected = descriptor(kind);
    if (message->header.messageId != expected.message_id ||
        message->header.protocolVersion != expected.protocol_version) return Result::invalid_argument;
    return Result::accepted;
}
Result validate_pdu(Kind kind, const vanetza::ByteBuffer& data, std::size_t maximum) {
    if (data.empty() || data.size() > maximum) return Result::invalid_argument;
    try {
        switch (kind) {
#if VIDF_CAM
            case Kind::cam: return check<Cam>(kind, data);
#endif
#if VIDF_DENM
            case Kind::denm: return check<Denm>(kind, data);
#endif
#if VIDF_VAM
            case Kind::vam: return check<Vam>(kind, data);
#endif
            default: return Result::unsupported;
        }
    } catch (const std::bad_alloc&) { return Result::resource_limit; }
      catch (const std::exception&) { return Result::invalid_argument; }
}
#if VIDF_NETWORK
Result send(Stack& stack, Kind kind, vanetza::ByteBuffer bytes, BtpRequest req) {
    auto result = validate_pdu(kind, bytes, stack.config().mib.itsGnMaxSduSize - 4u);
    if (result != Result::accepted) return result;
    req.type = BtpType::b;
    req.source_port.reset();
    req.destination_port = descriptor(kind).port;
    req.destination_port_info = 0;
    if (req.its_aid == 0) {
        // SN-ENCAP its_aid selects the security profile: TS 102 965 V2.4.1 Table A.1
        // (CA 36, DEN 37, VRU 638); TS 103 300-3 V2.3.1 clause 6.5.1 for VAMs.
        switch (kind) {
            case Kind::cam: req.its_aid = vanetza::aid::CA; break;
            case Kind::denm: req.its_aid = vanetza::aid::DEN; break;
            case Kind::vam: req.its_aid = vanetza::aid::VRU; break;
        }
    }
    if (kind == Kind::vam && req.permissions.empty()) {
        // TS 103 300-3 V2.3.1 clause 6.5.2: BitmapSsp whose first octet, value 1, is the SSP version.
        req.permissions = {0x01};
    }
    req.data = std::move(bytes);
    return stack.request(std::move(req));
}
#endif
}
