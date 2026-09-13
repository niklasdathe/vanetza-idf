#pragma once
#include <vanetza_idf/security.hpp>
#include <vanetza/common/its_aid.hpp>
#include <optional>
#include <utility>
#include <vector>

/** SF-SAP language binding: TS 102 723-9 V1.1.1 (interface between the
 * security entity and the facilities layer). Tables 10 to 21 carry the same
 * parameters as the SN-SAP identifier-change primitives of TS 102 723-8, and
 * clause 4.1.5 allows one security entity to serve several layers: the SF
 * primitives below are served by the same IdChangeService instance the GN
 * core subscribes to. TS 103 300-3 V2.3.1 clause 5.3.5 requires the VRU
 * basic service to subscribe, stop generating VAMs on PREPARE, resume after
 * COMMIT with a new StationId, and to use the lock for elevated-hazard
 * situations. The facilities-side subscriber may run in the same task, in
 * another task or process, or on another device; the library defines no
 * transport, only these bindings.
 *
 * SF-SIGN/-VERIFY/-ENCRYPT/-DECRYPT/-ENCAP/-DECAP (Tables 2 to 9, 24 to 27)
 * are declared as parameter types only: for messages carried over BTP and
 * GeoNetworking the security envelope is applied at the GeoNetworking layer
 * (TS 103 300-3 clause 6.5.1; TS 103 836-4-1 clause 10.3.10.2 SN-ENCAP), so
 * this library provides no facilities-level signing service.
 */
namespace vanetza_idf::SF_SAP {

using security::Identifier;
using security::IdChangeCommand;
using security::LockHandle;
using security::SubscriptionHandle;

/// Table 10: SF-IDCHANGE-SUBSCRIBE.request
struct SF_IDCHANGE_SUBSCRIBE_request {
    security::IdChangeHook idchange_event_hook; // Mandatory, signature of clause 5.2.6
    vanetza::ByteBuffer subscriber_data;         // Optional
};
/// Table 11: SF-IDCHANGE-SUBSCRIBE.confirm
struct SF_IDCHANGE_SUBSCRIBE_confirm { SubscriptionHandle subscription; };
/// Table 12: SF-IDCHANGE-EVENT.indication (the hook arguments)
struct SF_IDCHANGE_EVENT_indication {
    IdChangeCommand command;
    Identifier id;
    vanetza::ByteBuffer subscriber_data;
};
/// Table 13: SF-IDCHANGE-EVENT.response
struct SF_IDCHANGE_EVENT_response { bool return_code; };
/// Table 14: SF-IDCHANGE-UNSUBSCRIBE.request; Table 15 confirm carries no parameter
struct SF_IDCHANGE_UNSUBSCRIBE_request { SubscriptionHandle subscription; };
/// Tables 16/17: SF-IDCHANGE-TRIGGER.request/.confirm carry no parameter
struct SF_IDCHANGE_TRIGGER_request {};
/// Table 18: SF-ID-LOCK.request
struct SF_ID_LOCK_request { std::uint8_t Duration; };
/// Table 19: SF-ID-LOCK.confirm
struct SF_ID_LOCK_confirm { LockHandle lock_handle; };
/// Table 20: SF-ID-UNLOCK.request; Table 21 confirm carries no parameter
struct SF_ID_UNLOCK_request { LockHandle lock_handle; };
/// Clause 5.2.11 / Table 22 (message example): SF-LOG-SECURITY-EVENT.request
using SF_LOG_SECURITY_EVENT_request = security::SecurityEvent;

/// TS 102 723-9 V1.1.1 clause 5.2.5: SF-IDCHANGE-SUBSCRIBE (Tables 10/11)
inline SF_IDCHANGE_SUBSCRIBE_confirm SF_IDCHANGE_SUBSCRIBE_request_submit(security::IdChangeService& service,
                                                                          SF_IDCHANGE_SUBSCRIBE_request primitive) {
    return {service.subscribe(std::move(primitive.idchange_event_hook), std::move(primitive.subscriber_data))};
}
/// Clause 5.2.7: SF-IDCHANGE-UNSUBSCRIBE (Tables 14/15)
inline Result SF_IDCHANGE_UNSUBSCRIBE_request_submit(security::IdChangeService& service,
                                                     SF_IDCHANGE_UNSUBSCRIBE_request primitive) {
    return service.unsubscribe(primitive.subscription);
}
/// Clause 5.2.8: SF-IDCHANGE-TRIGGER (Tables 16/17)
inline Result SF_IDCHANGE_TRIGGER_request_submit(security::IdChangeService& service, SF_IDCHANGE_TRIGGER_request) {
    return service.trigger();
}
/// Clause 5.2.9: SF-ID-LOCK (Tables 18/19), Duration in seconds 0..255
inline SF_ID_LOCK_confirm SF_ID_LOCK_request_submit(security::IdChangeService& service, SF_ID_LOCK_request primitive) {
    return {service.lock(primitive.Duration)};
}
/// Clause 5.2.10: SF-ID-UNLOCK (Tables 20/21)
inline Result SF_ID_UNLOCK_request_submit(security::IdChangeService& service, SF_ID_UNLOCK_request primitive) {
    return service.unlock(primitive.lock_handle);
}
/// Clause 5.2.11: SF-LOG-SECURITY-EVENT (Tables 22/23)
inline void SF_LOG_SECURITY_EVENT_request_submit(security::SecurityEntity& entity,
                                                 SF_LOG_SECURITY_EVENT_request primitive) {
    entity.log_security_event(std::move(primitive));
}

// ---- Parameter types only (see the header comment) -------------------------

/// Table 2: SF-SIGN.request
struct SF_SIGN_request {
    std::size_t tbs_message_length = 0;
    vanetza::ByteBuffer tbs_message;
    vanetza::ItsAid its_aid = 0;
    std::size_t permissions_length = 0;
    vanetza::ByteBuffer Permissions; // <= 31 octets, SSP of the ITS-AID
    vanetza::ByteBuffer context_information; // Optional
    std::optional<std::uint64_t> key_handle;  // Optional
};
/// Table 3: SF-SIGN.confirm
struct SF_SIGN_confirm { std::size_t sec_message_length = 0; vanetza::ByteBuffer sec_message; };
/// Table 4: SF-VERIFY.request
struct SF_VERIFY_request {
    std::size_t sec_header_length = 0;
    vanetza::ByteBuffer sec_header;
    std::size_t message_length = 0;
    vanetza::ByteBuffer message;
};
/// Table 5: SF-VERIFY.confirm (report values of TS 102 723-8 Table 27 / vanetza::security::VerificationReport)
struct SF_VERIFY_confirm {
    vanetza::security::VerificationReport report;
    std::optional<security::HashedId8> certificate_id;
    std::size_t its_aid_length = 0;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
};
/// Table 6: SF-ENCRYPT.request
struct SF_ENCRYPT_request {
    std::size_t tbe_payload_length = 0;
    vanetza::ByteBuffer tbe_payload;
    std::size_t target_id_list_length = 0;
    std::vector<security::HashedId8> target_id_list;
    vanetza::ByteBuffer context_information; // Optional
};
/// Table 7: SF-ENCRYPT.confirm
struct SF_ENCRYPT_confirm { std::size_t encrypted_message_length = 0; vanetza::ByteBuffer encrypted_message; };
/// Table 8: SF-DECRYPT.request
struct SF_DECRYPT_request { std::size_t encrypted_message_length = 0; vanetza::ByteBuffer encrypted_message; };
/// Table 9: SF-DECRYPT.confirm
struct SF_DECRYPT_confirm {
    enum class Report : std::uint8_t { SUCCESS, UNENCRYPTED_MESSAGE, DECRYPTION_ERROR, INCOMPATIBLE_PROTOCOL };
    std::size_t plaintext_message_length = 0;
    vanetza::ByteBuffer plaintext_message;
    Report report;
};
/// Table 24: SF-ENCAP.request (identical parameters to SN-ENCAP.request)
struct SF_ENCAP_request {
    std::size_t tbe_packet_length = 0;
    vanetza::ByteBuffer tbe_packet;
    std::optional<std::uint16_t> sec_services;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
    vanetza::ByteBuffer context_information;
    std::vector<security::HashedId8> target_id_list;
};
/// Table 25: SF-ENCAP.confirm
struct SF_ENCAP_confirm { std::size_t sec_packet_length = 0; vanetza::ByteBuffer sec_packet; };
/// Table 26: SF-DECAP.request
struct SF_DECAP_request { std::size_t sec_packet_length = 0; vanetza::ByteBuffer sec_packet; };
/// Table 27: SF-DECAP.confirm
struct SF_DECAP_confirm {
    std::size_t plaintext_packet_length = 0;
    vanetza::ByteBuffer plaintext_packet;
    vanetza::security::VerificationReport report;
    std::optional<security::HashedId8> certificate_id;
    std::size_t its_aid_length = 0;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
};

} // namespace vanetza_idf::SF_SAP
