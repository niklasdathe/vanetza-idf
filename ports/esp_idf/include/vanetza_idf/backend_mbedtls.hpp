#pragma once
#include <vanetza/security/backend.hpp>
#include <memory>

namespace vanetza_idf {

/** vanetza::security::Backend on the PSA Crypto API of mbedTLS.
 *
 * ESP-IDF 6.0.2 ships mbedTLS 4.1.0 (TF-PSA-Crypto), where the classic
 * ecp/ecdsa/bignum headers are private; the PSA API (psa/crypto.h) is the only
 * public cryptography interface and is also present in mbedTLS 3.6 (ESP-IDF 5.x).
 *
 * Algorithms are those TS 103 097 V2.2.1 clause 5.2 selects through IEEE Std
 * 1609.2: ECDSA over NIST P-256, brainpoolP256r1 (SHA-256) and brainpoolP384r1
 * (SHA-384), clauses 5.3.1, 5.3.3, 6.3.38/6.3.39. ECDSA is randomized
 * (PSA_ALG_ECDSA(SHA-256/SHA-384) over the caller-supplied digest of that
 * length, which lets ESP-IDF's PSA driver use the ESP32-C5 ECDSA peripheral for
 * verification; IEEE Std 1609.2 does not require RFC 6979). Compressed points
 * are recovered by vanetza_idf::ecc, since PSA imports Weierstrass public keys
 * only in SEC 1 uncompressed form.
 *
 * Private keys are imported as volatile PSA keys the first time they are used
 * and kept in a small bounded cache until the backend is destroyed. Every
 * failure raises std::runtime_error or returns false; nothing is faked.
 */
class BackendMbedTls : public vanetza::security::Backend {
public:
    static constexpr auto backend_name = "mbedTLS-PSA";

    BackendMbedTls();
    ~BackendMbedTls() override;
    BackendMbedTls(const BackendMbedTls&) = delete;
    BackendMbedTls& operator=(const BackendMbedTls&) = delete;

    /// Legacy NIST P-256 + SHA-256 signature of data (TS 103 097 v1.x, IEEE 1609.2 5.3.1)
    vanetza::security::EcdsaSignature sign_data(const vanetza::security::ecdsa256::PrivateKey&,
                                                const vanetza::ByteBuffer& data) override;
    /// ECDSA over a precomputed digest; curve follows the key type
    vanetza::security::Signature sign_digest(const vanetza::security::PrivateKey&,
                                             const vanetza::ByteBuffer& digest) override;
    bool verify_data(const vanetza::security::ecdsa256::PublicKey&, const vanetza::ByteBuffer& data,
                     const vanetza::security::EcdsaSignature&) override;
    bool verify_digest(const vanetza::security::PublicKey&, const vanetza::ByteBuffer& digest,
                       const vanetza::security::Signature&) override;
    /// NIST P-256 only, matching the upstream OpenSSL backend (EccPoint carries no curve)
    boost::optional<vanetza::security::Uncompressed> decompress_point(const vanetza::security::EccPoint&) override;
    vanetza::ByteBuffer calculate_hash(vanetza::security::HashAlgorithm, const vanetza::ByteBuffer&) override;
    /// Fresh NIST P-256 key pair from the PSA random generator
    vanetza::security::ecdsa256::KeyPair generate_key_pair() override;

    /** Maximum number of imported private keys kept resident (default 4:
     * the current and next authorization tickets plus enrolment material). */
    void set_key_cache_size(std::size_t);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace vanetza_idf
