#pragma once
#include <vanetza_idf/security.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/net/osi_layer.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/security/secured_message.hpp>
#include <boost/iostreams/stream.hpp>
#include <optional>
#include <utility>
#include <vector>

/** SN-SAP language binding: TS 102 723-8 V2.0.0 clause 5 incorporates V1.1.1,
 * whose Tables 10 to 27 define the primitives below. '-' and '.' in primitive
 * names become '_'; parameters keep the tables' names in snake_case. The
 * *_submit functions are thin calls into the security entity, like
 * NF_SAP::BTP_DATA_request_submit. Inside the stack the GeoNetworking router
 * calls the same entity directly (vanetza::security::SecurityEntity), so
 * these bindings serve a caller in another task, process or device and the
 * test adapters; the library defines no transport for that.
 */
namespace vanetza_idf::SN_SAP {

using security::Identifier;
using security::IdChangeCommand;
using security::LockHandle;
using security::SubscriptionHandle;

/// TS 102 723-8 V1.1.1 Table 10: SN-IDCHANGE-SUBSCRIBE.request
struct SN_IDCHANGE_SUBSCRIBE_request {
    security::IdChangeHook idchange_event_hook; // Mandatory: hook function, signature of clause 5.2.6
    vanetza::ByteBuffer subscriber_data;         // Optional: passed back on every hook call
};
/// Table 11: SN-IDCHANGE-SUBSCRIBE.confirm
struct SN_IDCHANGE_SUBSCRIBE_confirm {
    SubscriptionHandle subscription; // INTEGER 0 to 2^64-1
};
/// Table 12: SN-IDCHANGE-EVENT.indication (the arguments of the hook function)
struct SN_IDCHANGE_EVENT_indication {
    IdChangeCommand command;             // PREPARE, COMMIT, ABORT, DEREG (clause 6.3)
    Identifier id;                       // OCTET STRING, 8 octets: id to be set
    vanetza::ByteBuffer subscriber_data; // Optional
};
/// Table 13: SN-IDCHANGE-EVENT.response
struct SN_IDCHANGE_EVENT_response {
    bool return_code; // acknowledgement to the given command
};
/// Table 14: SN-IDCHANGE-UNSUBSCRIBE.request; Table 15 confirm carries no parameter
struct SN_IDCHANGE_UNSUBSCRIBE_request {
    SubscriptionHandle subscription;
};
/// Table 16/17: SN-IDCHANGE-TRIGGER.request/.confirm carry no parameter
struct SN_IDCHANGE_TRIGGER_request {};
/// Table 18: SN-ID-LOCK.request
struct SN_ID_LOCK_request {
    std::uint8_t Duration; // INTEGER 0 to 2^8-1: number of seconds to lock
};
/// Table 19: SN-ID-LOCK.confirm
struct SN_ID_LOCK_confirm {
    LockHandle lock_handle; // INTEGER 0 to 2^64-1: handle to unlock manually
};
/// Table 20: SN-ID-UNLOCK.request; Table 21 confirm carries no parameter
struct SN_ID_UNLOCK_request {
    LockHandle lock_handle;
};
/// Table 22: SN-LOG-SECURITY-EVENT.request; Table 23 confirm carries no parameter
using SN_LOG_SECURITY_EVENT_request = security::SecurityEvent;

/// Table 24: SN-ENCAP.request (the GeoNetworking source fills it per TS 103 836-4-1 V2.2.1 Table 34)
struct SN_ENCAP_request {
    std::size_t tbe_packet_length = 0;           // Mandatory: length of tbe_packet
    vanetza::ByteBuffer tbe_packet;              // Mandatory: packet to encapsulate (Common Header onwards)
    std::optional<std::uint16_t> sec_services;   // Optional: security service(s) to invoke
    vanetza::ItsAid its_aid = 0;                 // Mandatory: ITS-AID selecting the security profile
    vanetza::ByteBuffer permissions;             // Mandatory: SSP associated with the ITS-AID (<= 31 octets)
    vanetza::ByteBuffer context_information;     // Optional: opaque, see security::context
    std::vector<security::HashedId8> target_id_list; // Optional: recipients (encryption is not implemented)
};
/// Table 25: SN-ENCAP.confirm
struct SN_ENCAP_confirm {
    std::size_t sec_packet_length = 0;
    vanetza::ByteBuffer sec_packet; // the Secured Packet, EtsiTs103097Data (COER)
};

inline SN_IDCHANGE_SUBSCRIBE_confirm SN_IDCHANGE_SUBSCRIBE_request_submit(security::IdChangeService& service,
                                                                          SN_IDCHANGE_SUBSCRIBE_request primitive) {
    return {service.subscribe(std::move(primitive.idchange_event_hook), std::move(primitive.subscriber_data))};
}
inline Result SN_IDCHANGE_UNSUBSCRIBE_request_submit(security::IdChangeService& service,
                                                     SN_IDCHANGE_UNSUBSCRIBE_request primitive) {
    return service.unsubscribe(primitive.subscription);
}
inline Result SN_IDCHANGE_TRIGGER_request_submit(security::IdChangeService& service, SN_IDCHANGE_TRIGGER_request) {
    return service.trigger();
}
inline SN_ID_LOCK_confirm SN_ID_LOCK_request_submit(security::IdChangeService& service, SN_ID_LOCK_request primitive) {
    return {service.lock(primitive.Duration)};
}
inline Result SN_ID_UNLOCK_request_submit(security::IdChangeService& service, SN_ID_UNLOCK_request primitive) {
    return service.unlock(primitive.lock_handle);
}
inline void SN_LOG_SECURITY_EVENT_request_submit(security::SecurityEntity& entity,
                                                 SN_LOG_SECURITY_EVENT_request primitive) {
    entity.log_security_event(std::move(primitive));
}

/** SN-ENCAP over raw octets. Result::invalid_argument on a length mismatch or a
 * permissions field beyond 31 octets, Result::unsupported when sec_services or
 * target_id_list request anything but signing, Result::security_unavailable
 * when the entity refuses (no usable ticket, identifier change pending). */
inline Result SN_ENCAP_request_submit(vanetza::security::SecurityEntity& entity, SN_ENCAP_request primitive,
                                      SN_ENCAP_confirm& confirm) {
    if (primitive.tbe_packet_length != primitive.tbe_packet.size() || primitive.tbe_packet.empty() ||
        primitive.permissions.size() > 31) return Result::invalid_argument;
    if (primitive.sec_services || !primitive.target_id_list.empty()) return Result::unsupported;
    vanetza::security::SignRequest request;
    request.plain_message[vanetza::OsiLayer::Network] = std::move(primitive.tbe_packet);
    request.its_aid = primitive.its_aid;
    request.permissions = std::move(primitive.permissions);
    request.context_information = std::move(primitive.context_information);
    auto result = entity.encapsulate_packet(vanetza::security::EncapRequest {std::move(request)});
    const auto* secured = result.secured_message();
    if (!secured) return Result::security_unavailable;
    confirm.sec_packet.clear();
    vanetza::byte_buffer_sink sink(confirm.sec_packet);
    boost::iostreams::stream_buffer<vanetza::byte_buffer_sink> stream(sink);
    vanetza::OutputArchive archive(stream);
    vanetza::security::serialize(archive, *secured);
    stream.pubsync();
    confirm.sec_packet_length = confirm.sec_packet.size();
    return Result::accepted;
}

} // namespace vanetza_idf::SN_SAP
