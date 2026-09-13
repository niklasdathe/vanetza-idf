// Cryptographic digest adapter for upstream certificate/envelope helpers.
// Algorithms are supplied by ESP-IDF PSA Crypto or host OpenSSL, never a dummy.
#include <vanetza/security/sha.hpp>
#include <stdexcept>
#ifdef ESP_PLATFORM
#include <psa/crypto.h>
#else
#include <openssl/sha.h>
#endif

namespace vanetza::security {
Sha256Digest calculate_sha256_digest(const std::uint8_t* data, std::size_t size) {
    Sha256Digest digest {};
#ifdef ESP_PLATFORM
    std::size_t written = 0;
    if (psa_crypto_init() != PSA_SUCCESS ||
        psa_hash_compute(PSA_ALG_SHA_256, data, size, digest.data(), digest.size(), &written) != PSA_SUCCESS ||
        written != digest.size()) throw std::runtime_error("SHA-256 unavailable");
#else
    if (!SHA256(data, size, digest.data())) throw std::runtime_error("SHA-256 failed");
#endif
    return digest;
}
Sha384Digest calculate_sha384_digest(const std::uint8_t* data, std::size_t size) {
    Sha384Digest digest {};
#ifdef ESP_PLATFORM
    std::size_t written = 0;
    if (psa_crypto_init() != PSA_SUCCESS ||
        psa_hash_compute(PSA_ALG_SHA_384, data, size, digest.data(), digest.size(), &written) != PSA_SUCCESS ||
        written != digest.size()) throw std::runtime_error("SHA-384 unavailable");
#else
    if (!SHA384(data, size, digest.data())) throw std::runtime_error("SHA-384 failed");
#endif
    return digest;
}
}
