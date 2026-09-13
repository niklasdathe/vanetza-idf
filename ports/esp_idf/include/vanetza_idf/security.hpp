#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza_idf/id_change.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/location_checker.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <deque>
#include <functional>
#include <memory>
#include <vector>

/** Signing security entity for the SN-SAP.
 *
 * Standards: TS 103 097 V2.2.1 (secured message and certificate formats,
 * clause 5.2 SignedData constraints, clause 7 profiles), IEEE Std 1609.2
 * (hashing and ECDSA, clause 5.3), TS 102 940 V2.1.1 (trust model: root CA ->
 * AA -> authorization ticket, clause 6.5 identity management), TS 102 941
 * V2.2.1 (credential life cycle), TS 102 723-8 V2.0.0/V1.1.1 (SN-SAP
 * primitives), TS 103 300-3 V2.3.1 clause 6.5 (VAM signing and certificate
 * attachment). Verification of received messages (SN-DECAP) is not
 * implemented; see docs/idf/conformance.md GAP-SEC-001.
 */
namespace vanetza_idf::security {

using vanetza::ByteBuffer;
using vanetza::security::HashedId8;
using vanetza::security::PrivateKey;
using vanetza::security::v3::Certificate;

/** SN-ENCAP.request context_information values understood by this entity
 * (TS 102 723-8 V1.1.1 Table 24: opaque octets "used in selecting properties
 * of the underlying security protocol"; the standard leaves the content to the
 * implementation, these values are this library's definition). */
namespace context {
/// VAM generated for a VRU cluster: TS 103 300-3 V2.3.1 clause 6.5.3 500 ms certificate cadence
inline const ByteBuffer vam_cluster {0x01};
}

/** Authorization tickets owned by this station together with their private keys.
 *
 * TS 103 097 V2.2.1 clause 7.2.1 (AT profile), TS 102 940 V2.1.1 clause 6.5
 * ("multiple authorization tickets ... to be used ... over its life time").
 * Tickets are provisioned by the application, e.g. from files written by the
 * station's own PKI (COER EtsiTs103097Certificate plus raw private key, the
 * formats of vanetza::security::v3::load_certificate_from_file and
 * load_private_key_from_*_file) or from a TS 102 941 authorization response.
 */
class CertificatePool : public vanetza::security::v3::BaseCertificateProvider {
public:
    /// An authorization ticket (TS 103 097 V2.2.1 clause 7.2.1 profile) with the private
    /// key of its verifyKeyIndicator; the pool owns both.
    struct Ticket {
        Certificate certificate;
        PrivateKey key;
        HashedId8 digest; // HashedId8 per TS 103 097 clause 6 / IEEE 1609.2 clause 6.4.3
    };

    explicit CertificatePool(vanetza::security::Backend&);

    /** Add a ticket. Fails closed (Result::invalid_argument) when the certificate
     * does not decode, is not an authorization ticket (clause 7.2.1: issuer
     * sha256AndDigest/sha384AndDigest, appPermissions present, no
     * certIssuePermissions), the key type or length does not match the
     * verification key, or the private key does not belong to the certificate
     * (checked by a sign/verify round trip). Duplicate digests are rejected. */
    Result add(const ByteBuffer& coer_certificate, const PrivateKey&);
    Result add(Certificate, PrivateKey);

    /// pool bookkeeping for the application's provisioning and persistence
    std::size_t size() const { return tickets_.size(); }
    bool empty() const { return tickets_.empty(); }
    const std::vector<Ticket>& tickets() const { return tickets_; }
    /// currently selected ticket, nullptr when the pool is empty
    const Ticket* current() const;
    /// next different ticket valid at now (round robin), nullptr when none
    const Ticket* next_valid(vanetza::Clock::time_point now) const;
    /// make the ticket with this digest current (identifier change COMMIT)
    Result select(const HashedId8&);
    /// drop tickets whose validity ended before now, never the current one; returns count
    std::size_t prune(vanetza::Clock::time_point now);

    // v3::CertificateProvider: the current ticket; std::logic_error when empty
    const Certificate& own_certificate() override;
    const PrivateKey& own_private_key() override;

private:
    vanetza::security::Backend& backend_;
    std::vector<Ticket> tickets_;
    std::size_t current_ = 0;
};

/** Trust anchors and issuing authorities supplied by the application.
 * TS 102 940 V2.1.1 clause 6.1 (root CA, AA), TS 103 097 clauses 7.2.3/7.2.4;
 * TS 102 941 V2.2.1 clause 6.3 CTL/CRL retrieval is not part of this library. */
class TrustConfiguration {
public:
    /// self-signed root CA certificate (clause 7.2.3) -> trust store and issuer lookup
    Result add_root(const ByteBuffer& coer_certificate);
    Result add_root(const Certificate&);
    /// AA or other subordinate CA certificate (clause 7.2.4) -> issuer lookup
    Result add_authority(const ByteBuffer& coer_certificate);
    Result add_authority(const Certificate&);

    const vanetza::security::v3::TrustStore& roots() const { return roots_; }
    const vanetza::security::v3::IssuerMemoryLookup& issuers() const { return issuers_; }
    /// every CA certificate added (for P2P certificate distribution lookups by HashedId3)
    const std::vector<Certificate>& authorities() const { return authorities_; }

private:
    vanetza::security::v3::TrustStore roots_;
    vanetza::security::v3::IssuerMemoryLookup issuers_;
    std::vector<Certificate> authorities_;
};

/** Header fields and signer identifier per message profile.
 *
 * TS 103 097 V2.2.1 clause 5.2: psid and generationTime always present,
 * p2pcdLearningRequest and missingCrlIdentifier always absent.
 * - CAM (ITS-AID 36, TS 102 965 Table A.1): clause 7.1.1 - digest by default,
 *   certificate once one second after its last inclusion, immediately after a
 *   CAM from an unknown AT (request_certificate) or an inline P2PCD request for
 *   our AT, inlineP2pcdRequest for unknown certificates, requestedCertificate
 *   for known CA certificates; no other header fields.
 * - DENM (37): clause 7.1.2 - certificate always, generationLocation present.
 * - VAM (638): TS 103 300-3 V2.3.1 clause 6.5.3 - individual VAM: certificate
 *   if >= 1 s since the last certificate attached to a VAM or a new CAM signer
 *   was observed (report_new_cam_signer), else digest; cluster VAM (SN-ENCAP
 *   context_information == context::vam_cluster): certificate if >= 500 ms,
 *   else digest.
 * - other ITS-AIDs, including GN-MGMT beacons (141): clause 7.1.3 generic
 *   profile, which constrains only clause 5.2; this library includes the
 *   certificate once per second per ITS-AID and the digest otherwise.
 */
class Ts103097SignHeaderPolicy : public vanetza::security::v3::SignHeaderPolicy {
public:
    Ts103097SignHeaderPolicy(const vanetza::Runtime&, vanetza::PositionProvider&, CertificatePool&,
                             const TrustConfiguration&);
    ~Ts103097SignHeaderPolicy() override;
    void prepare_header(const vanetza::security::SignRequest&, vanetza::security::v3::SecuredMessage&) override;
    void request_unrecognized_certificate(HashedId8) override;
    void request_certificate() override;
    void enqueue_p2p_request(vanetza::security::HashedId3) override;
    void discard_p2p_request(vanetza::security::HashedId3) override;
    /// TS 103 300-3 clause 6.5.3 item 2: a CAM was received from a not previously seen signer
    void report_new_cam_signer();
    /// after an identifier change the new ticket has never been announced: attach it next
    void reset_after_identifier_change();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/** SN-LOG-SECURITY-EVENT.request (TS 102 723-8 V1.1.1 Table 22). Events are
 * kept in a bounded log the application can drain for misbehaviour reporting. */
struct SecurityEvent {
    enum class Type : std::uint8_t {
        TIME_CONSISTENCY_FAILED, LOCATION_CONSISTENCY_FAILED, ID_CONSISTENCY_FAILED,
        DISALLOWED_MESSAGE_CONTENT, DISALLOWED_MESSAGE_FREQUENCY, REPLAY_DETECTION_TIME,
        REPLAY_DETECTION_LOCATION, MOVEMENT_PLAUSIBILITY, APPEARANCE_PLAUSIBILITY,
        LOCATION_PLAUSIBILITY_SENSOR, LOCATION_PLAUSIBILITY_MAP, LOCATION_PLAUSIBILITY_CONTRADICTION,
        APPLICATION_SPECIFIC
    };
    struct Location { std::int32_t latitude; std::int32_t longitude; };
    struct Evidence { std::uint8_t type; ByteBuffer content; }; // event_evidence_type/content
    Type event_type;
    std::vector<HashedId8> neighbour_id_list;
    std::uint32_t event_time; // INTEGER 0..2^32-1, shall be in the past
    std::optional<Location> event_location;
    std::vector<Evidence> event_evidence_list;
};

class IdentityManager;

/** The security entity: SN-ENCAP/SN-DECAP plus the identifier-change service.
 * Runtime, position provider, backend, pool and trust configuration are
 * owned by the application and must outlive the entity. All calls come from
 * the one task that also drives the stack. */
class SecurityEntity : public vanetza::security::SecurityEntity {
public:
    SecurityEntity(vanetza::Runtime&, vanetza::PositionProvider&, vanetza::security::Backend&, CertificatePool&,
                   const TrustConfiguration&);
    ~SecurityEntity() override;

    /** SN-ENCAP.request/.confirm (TS 102 723-8 V1.1.1 Tables 24/25; TS 103 836-4-1 V2.2.1
     * Table 34). Refused (SignConfirmError::No_Certificate) when the pool is empty, the current
     * ticket is not valid for the ITS-AID, or an identifier change is between PREPARE and COMMIT
     * (clause 6.3.1.3: messages with old identifiers shall be avoided). */
    vanetza::security::EncapConfirm encapsulate_packet(vanetza::security::EncapRequest&&) override;

    /** SN-DECAP.request/.confirm (Tables 26/27). Verification is not implemented: unsigned
     * messages report UNSIGNED_MESSAGE, signed messages report Configuration_Problem (the
     * entity is not configured to verify) with the payload and unverified ITS-AID attached
     * so a receiver with itsGnSnDecapResultHandling = STRICT drops them. Never a success. */
    vanetza::security::DecapConfirm decapsulate_packet(vanetza::security::DecapRequest&&) override;

    /// SN-LOG-SECURITY-EVENT.request (Table 22); .confirm has no parameters (Table 23)
    void log_security_event(SecurityEvent);
    /// take all logged events, oldest first
    std::deque<SecurityEvent> drain_security_events();
    void set_security_event_capacity(std::size_t);

    /** Outcome counters. The GN router reports GN-DATA.confirm before SN-ENCAP runs
     * (TS 103 836-4-1 clause 10.3.10.2 step 2 happens at transmission), so a refused
     * encapsulation is visible here and in the absence of a packet, not in Stack::request. */
    struct Statistics { unsigned signed_messages = 0, refused_no_ticket = 0, refused_change_pending = 0,
                        refused_permission = 0, failed = 0; };
    const Statistics& statistics() const;

    IdChangeService& id_change();
    const IdChangeService& id_change() const;
    IdentityManager& identity_manager();
    Ts103097SignHeaderPolicy& header_policy();
    vanetza::security::v3::DefaultCertificateValidator& validator();
    CertificatePool& certificates();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/** TS 102 723-8 V1.1.1 clause 6.3 implementation: subscriptions, the two-phase commit
 * (clause 6.3.1.3, Figures 11 to 13), locks with automatic release (clause 6.3.2,
 * Table 18) and deferred triggers (clause 6.3.3). New identifier = HashedId8 of the
 * next authorization ticket in the pool (TS 102 940 V2.1.1 clause 6.5). */
class IdentityManager : public IdChangeService {
public:
    IdentityManager(vanetza::Runtime&, CertificatePool&);
    ~IdentityManager() override; // DEREG to every subscriber (Figure 15)

    SubscriptionHandle subscribe(IdChangeHook, ByteBuffer subscriber_data = {}) override;
    Result unsubscribe(SubscriptionHandle) override;
    Result trigger() override;
    LockHandle lock(std::uint8_t duration_seconds) override;
    Result unlock(LockHandle) override;
    Identifier current_identifier() const override;
    bool change_pending() const override;

    /** Time allowed for all PREPARE (or COMMIT) responses before the change is aborted
     * (or the COMMIT is closed). Not specified by TS 102 723-8; library default 500 ms. */
    void set_response_timeout(vanetza::Clock::duration);
    /// invoked after a successful COMMIT with the new identifier
    void on_committed(std::function<void(const Identifier&)>);

    struct Statistics { unsigned committed = 0, aborted = 0, timed_out = 0, commit_failures = 0; };
    const Statistics& statistics() const;
    bool locked() const;

private:
    class Impl;
    std::shared_ptr<Impl> impl_; // responders keep a weak reference across the manager's lifetime
};

} // namespace vanetza_idf::security
