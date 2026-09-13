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

    /// IEEE 1609.2 clause 5.3.1 check of a certificate signature against its issuer (or itself)
    bool verify_chain_signature(const vanetza::security::v3::Certificate& subject,
                                const vanetza::security::v3::Certificate& issuer) const;

    Credential root;
    Credential aa;

private:
    struct KeyMaterial { vanetza::security::PrivateKey priv; vanetza::security::PublicKey pub; };
    vanetza::security::Backend& backend_;
    KeyMaterial fresh_key() const; // NIST P-256 from Backend::generate_key_pair
    void sign(vanetza::security::v3::Certificate& subject, const vanetza::security::v3::Certificate* issuer,
              const vanetza::security::PrivateKey& issuer_key) const;
};

} // namespace vidf_test
