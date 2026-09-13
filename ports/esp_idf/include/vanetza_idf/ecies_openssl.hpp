#pragma once
#include <vanetza_idf/pki.hpp>

namespace vanetza_idf::pki {

/// EciesBackend on OpenSSL (host builds only): ECDH via EC_KEY, HMAC-SHA256, RAND_bytes, EVP AES-128-CCM.
class EciesOpenSsl : public EciesBackend {
public:
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
