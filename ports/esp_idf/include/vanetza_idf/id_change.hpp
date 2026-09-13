#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <cstdint>
#include <functional>
#include <memory>

namespace vanetza_idf::security {

/** Identifier-change service of the security entity.
 *
 * TS 102 723-8 V2.0.0 clause 5 incorporates V1.1.1: clauses 5.2.5 to 5.2.10
 * (SN-IDCHANGE-SUBSCRIBE/-EVENT/-UNSUBSCRIBE/-TRIGGER, SN-ID-LOCK/-UNLOCK) and
 * clause 6.3 (ID management: hook function, two-phase commit, lock, trigger).
 * TS 102 723-9 V1.1.1 clauses 5.2.5 to 5.2.10 define the identical SF-SAP
 * primitives (Tables 10 to 21 carry the same names and ranges), and clause
 * 4.1.5 allows one security entity to serve several layers, so one service
 * instance is exposed through both sn_sap.hpp and sf_sap.hpp. TS 102 940
 * V2.1.1 clause 6.5 requires every layer holding an identifier to subscribe
 * and derive its identifier from the HashedId8 given in the event.
 *
 * A subscriber may live in the same task, another task or process, or another
 * device: the hook is an ordinary callback and the response object may be used
 * inside the callback or later. The library defines no transport for that.
 */

/// SN-IDCHANGE-EVENT.indication command (TS 102 723-8 V1.1.1 Table 12; clause 6.3.1.2 a-d)
enum class IdChangeCommand : std::uint8_t { PREPARE, COMMIT, ABORT, DEREG };

/// Table 11 / Table 14 subscription: INTEGER 0 to 2^64-1
using SubscriptionHandle = std::uint64_t;
/// Table 19 / Table 20 lock_handle: INTEGER 0 to 2^64-1
using LockHandle = std::uint64_t;
/// Table 12 id: OCTET STRING of 8 octets, the HashedId8 of the authorization ticket (TS 102 940 clause 6.5)
using Identifier = vanetza::security::HashedId8;

/** SN-IDCHANGE-EVENT.response (Table 13 return_code).
 * Hand the object back within the hook call for a local subscriber, or keep it
 * and respond once the remote party has answered. Responding twice, or after
 * the phase finished (timeout, abort, unsubscribe), is ignored.
 */
class IdChangeResponder {
public:
    virtual void respond(bool return_code) = 0;
    virtual ~IdChangeResponder() = default;
};

/** Hook function (clause 6.3.1.2): command, id to be set and the subscriber_data
 * given at subscription (Table 12). For PREPARE and COMMIT the service waits
 * for the response; ABORT and DEREG expect no response (responder is null). */
using IdChangeHook = std::function<void(IdChangeCommand, const Identifier&, const vanetza::ByteBuffer& subscriber_data,
                                        std::shared_ptr<IdChangeResponder>)>;

/** The identifier-change service of the security entity (TS 102 723-8 V1.1.1 clause 6.3
 * "ID management"): SN-IDCHANGE-SUBSCRIBE/-UNSUBSCRIBE/-TRIGGER and SN-ID-LOCK/-UNLOCK
 * (clauses 5.2.5, 5.2.7 to 5.2.10) as virtual calls; the same instance serves the
 * SF-SAP (TS 102 723-9 V1.1.1 clauses 5.2.5 to 5.2.10). */
class IdChangeService {
public:
    virtual ~IdChangeService() = default;

    /// SN-IDCHANGE-SUBSCRIBE.request (Table 10) -> .confirm subscription (Table 11)
    virtual SubscriptionHandle subscribe(IdChangeHook idchange_event_hook, vanetza::ByteBuffer subscriber_data = {}) = 0;

    /// SN-IDCHANGE-UNSUBSCRIBE.request (Table 14); .confirm carries no parameter (Table 15)
    virtual Result unsubscribe(SubscriptionHandle subscription) = 0;

    /** SN-IDCHANGE-TRIGGER.request (Table 16). Queues an identifier change; clause 6.3.3 NOTE:
     * this does not lead to an immediate change, the two-phase commit is invoked, after any
     * lock is released. Result::rejected when no other valid authorization ticket exists. */
    virtual Result trigger() = 0;

    /// SN-ID-LOCK.request Duration 0..255 seconds (Table 18) -> lock_handle (Table 19); clause 6.3.2
    virtual LockHandle lock(std::uint8_t duration_seconds) = 0;

    /// SN-ID-UNLOCK.request (Table 20); .confirm carries no parameter (Table 21)
    virtual Result unlock(LockHandle lock_handle) = 0;

    /// HashedId8 of the authorization ticket currently in use (TS 102 940 clause 6.5)
    virtual Identifier current_identifier() const = 0;

    /// true while PREPARE has been issued and COMMIT/ABORT is outstanding (clause 6.3.1.3 item 2)
    virtual bool change_pending() const = 0;
};

} // namespace vanetza_idf::security
