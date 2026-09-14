#pragma once
#include <vanetza_idf/security.hpp>
#include <string>
#include <vector>

/** A station's provisioned credentials and how they are kept.
 *
 * TS 102 940 V2.1.1 clause 6 (trust model: root CA, EA/AA, tickets) and TS 102 941
 * V2.2.1 (credential life cycle) leave the obtaining and keeping of certificates to
 * the station; TS 102 723-8 has no primitive for it. The security entity takes
 * them as a TrustConfiguration and a CertificatePool (security.hpp). This header
 * fixes the octets in between: what a provisioning path of the application
 * (a file, a serial link, a wireless link, a TS 102 941 client) hands over and
 * what a storage keeps across resets. Certificates are COER EtsiTs103097Certificate
 * values (TS 103 097 V2.2.1 clause 6), ticket keys the raw private scalar of the
 * verification key (IEEE Std 1609.2 clause 6.4.36 curves), nothing else.
 *
 * Bundle format (this library's definition, version 1): the ASCII magic "VCR1"
 * followed by records [type: 1 octet][length: 2 octets, big-endian][payload].
 * Types: 1 root CA certificate, 2 subordinate CA certificate (AA/EA), 3 ticket
 * certificate, 4 ticket private key ([curve: 1 octet, 1 = NIST P-256, 2 =
 * brainpoolP256r1, 3 = brainpoolP384r1][scalar]) which follows its ticket
 * certificate. Decoding fails closed on any deviation. Keys travel and rest in
 * the clear: a transport must be a trusted one and a storage the application's
 * encrypted one (ESP-IDF NVS encryption for NvsCredentialStore).
 */
namespace vanetza_idf::security {

struct Credentials {
    struct Ticket {
        ByteBuffer certificate; // COER, TS 103 097 clause 7.2.1 profile
        PrivateKey key;         // private scalar of verifyKeyIndicator
    };
    std::vector<ByteBuffer> roots;       // clause 7.2.3, self-signed
    std::vector<ByteBuffer> authorities; // clause 7.2.4, issued by a root or another CA
    std::vector<Ticket> tickets;         // clause 7.2.1, with keys

    bool empty() const { return roots.empty() && authorities.empty() && tickets.empty(); }
};

/// bundle octets of the credentials (format above)
ByteBuffer encode(const Credentials&);
/// parse a bundle; false (and an untouched output) when the octets are not a well-formed bundle
bool decode(const ByteBuffer& bundle, Credentials& out);

/** Result of feeding credentials into the trust configuration and the pool: how many
 * of each were accepted and the first refusal (Result::accepted when everything was). */
struct ApplyReport {
    std::size_t roots = 0, authorities = 0, tickets = 0;
    Result result = Result::accepted;
};
/** Add every root, then every authority, then every ticket, each through the checks of
 * TrustConfiguration::add_* and CertificatePool::add (TS 103 097 profiles, key/certificate
 * match); stops at the first refusal so that a broken item is not silently skipped. */
ApplyReport apply(const Credentials&, TrustConfiguration&, CertificatePool&);

/** Storage the application chooses: keeps one bundle. load() returns Result::rejected
 * when nothing is stored and Result::invalid_argument when the stored octets do not
 * decode; save() replaces what was there; erase() removes it. */
class CredentialStore {
public:
    virtual ~CredentialStore() = default;
    virtual Result save(const Credentials&) = 0;
    virtual Result load(Credentials&) = 0;
    virtual Result erase() = 0;
};

/// a bundle in one file (hosts, or an ESP-IDF VFS the application mounted)
class FileCredentialStore final : public CredentialStore {
public:
    explicit FileCredentialStore(std::string path) : path_(std::move(path)) {}
    Result save(const Credentials&) override;
    Result load(Credentials&) override;
    Result erase() override;
private:
    std::string path_;
};

} // namespace vanetza_idf::security
