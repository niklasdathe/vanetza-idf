#pragma once
#include <vanetza_idf/pki.hpp>

namespace vanetza_idf::pki {

/** EciesBackend on the PSA Crypto API of mbedTLS (see backend_mbedtls.hpp for the
 * version rationale): psa_raw_key_agreement(PSA_ALG_ECDH) for the shared x
 * coordinate, psa_mac_compute(PSA_ALG_HMAC(SHA-256)), psa_generate_random and
 * psa_aead_encrypt/decrypt(PSA_ALG_CCM) with a 16-octet tag. */
class EciesMbedTls : public EciesBackend {
public:
    EciesMbedTls(); // psa_crypto_init, throws on failure
    KeyPair generate_key(KeyType) override;
    std::optional<ByteBuffer> ecdh_x(const PrivateKey& own, const PublicKey& peer) override;
    ByteBuffer hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) override;
    ByteBuffer random(std::size_t octets) override;
    bool aes_ccm_encrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                         const ByteBuffer& plaintext, ByteBuffer& ciphertext_and_tag) override;
    bool aes_ccm_decrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                         const ByteBuffer& ciphertext_and_tag, ByteBuffer& plaintext) override;
};

} // namespace vanetza_idf::pki
