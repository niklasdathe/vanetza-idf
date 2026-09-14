#pragma once
// Isolated TEST trust domain: a root CA, an authorization authority and
// authorization tickets generated on the fly with the host OpenSSL backend.
// Certificates follow TS 103 097 V2.2.1 clause 6 and clauses 7.2.1/7.2.3/7.2.4
// and carry IEEE Std 1609.2 clause 5.3.1 signatures (Hash(Hash(toBeSigned) ||
// Hash(issuer certificate)), empty string for self-signed). Keys and
// certificates never leave the test process; nothing here is a production PKI.
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace vidf_test {

struct Credential {
    vanetza::security::v3::Certificate certificate;
    vanetza::security::PrivateKey key;
};

class TrustDomain {
public:
    using Permissions = std::vector<std::pair<vanetza::ItsAid, vanetza::ByteBuffer>>;

    /// root and AA valid from now - 1 h; both may issue CA, DEN, VRU and GN-MGMT
    TrustDomain(vanetza::security::Backend&, vanetza::Clock::time_point now);

    /// authorization ticket (clause 7.2.1) issued by the AA
    Credential issue_ticket(const Permissions&, vanetza::Clock::time_point start, unsigned hours) const;
    /// the same, issued by another authority of this domain (see issue_authority)
    Credential issue_ticket(const Credential& authority, const Permissions&, vanetza::Clock::time_point start,
                            unsigned hours) const;
    /// IEEE Std 1609.2 CircularRegion (6.4.19): centre in 1/10 microdegrees, radius in metres
    struct CircularRegion { std::int32_t latitude; std::int32_t longitude; std::uint16_t radius_m; };
    /// the same ticket restricted to a circular region (TS 103 097 clause 7.2.1 allows region)
    Credential issue_ticket(const Credential& authority, const Permissions&, vanetza::Clock::time_point start,
                            unsigned hours, const CircularRegion& region) const;
    /// a further subordinate CA (clause 7.2.4) under the root, e.g. the test-system side authority
    Credential issue_authority(const std::string& name, vanetza::Clock::time_point start) const;
    /// AT for a verification key the station generated itself (TS 102 941 authorization); no private key
    vanetza::security::v3::Certificate issue_ticket_for(const vanetza::security::PublicKey& verification,
                                                        const Permissions&, vanetza::Clock::time_point start,
                                                        unsigned hours) const;
    /// enrolment credential (clause 7.2.2) issued by the EA for a station verification key
    vanetza::security::v3::Certificate issue_credential_for(const vanetza::security::PublicKey& verification,
                                                            const std::string& name, vanetza::Clock::time_point start,
                                                            unsigned hours) const;

    /// IEEE 1609.2 clause 5.3.1 check of a certificate signature against its issuer (or itself)
    bool verify_chain_signature(const vanetza::security::v3::Certificate& subject,
                                const vanetza::security::v3::Certificate& issuer) const;

    Credential root;
    Credential aa;
    Credential ea;                          // enrolment authority (clause 7.2.4), issued by the root
    vanetza::security::PrivateKey aa_encryption_key; // private part of the AA encryptionKey
    vanetza::security::PrivateKey ea_encryption_key; // private part of the EA encryptionKey

    // Building blocks, public so tests can construct deliberately wrong material (forged signatures).
    struct KeyMaterial { vanetza::security::PrivateKey priv; vanetza::security::PublicKey pub; };
    KeyMaterial fresh_key() const; // NIST P-256 from Backend::generate_key_pair
    /// IEEE 1609.2 clause 5.3.1 certificate signature with the given key (issuer nullptr: self-signed)
    void sign(vanetza::security::v3::Certificate& subject, const vanetza::security::v3::Certificate* issuer,
              const vanetza::security::PrivateKey& issuer_key) const;
private:
    vanetza::security::Backend& backend_;
};

} // namespace vidf_test
