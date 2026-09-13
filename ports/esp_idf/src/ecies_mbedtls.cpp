#include <vanetza_idf/ecies_mbedtls.hpp>
#include <vanetza_idf/ecc.hpp>
#include <psa/crypto.h>
#include <stdexcept>

namespace vanetza_idf::pki {
using namespace vanetza::security;
namespace {
psa_ecc_family_t family_of(KeyType type) {
    switch (type) {
        case KeyType::NistP256: return PSA_ECC_FAMILY_SECP_R1;
        case KeyType::BrainpoolP256r1:
        case KeyType::BrainpoolP384r1: return PSA_ECC_FAMILY_BRAINPOOL_P_R1;
        default: throw std::runtime_error("unsupported key type");
    }
}
struct ScopedKey {
    mbedtls_svc_key_id_t id = 0;
    ~ScopedKey() { if (id) psa_destroy_key(id); }
};
mbedtls_svc_key_id_t import_raw(psa_key_type_t type, std::size_t bits, psa_key_usage_t usage, psa_algorithm_t alg,
                                const std::uint8_t* data, std::size_t length) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, type);
    if (bits) psa_set_key_bits(&attributes, bits);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    mbedtls_svc_key_id_t id = 0;
    if (psa_import_key(&attributes, data, length, &id) != PSA_SUCCESS) throw std::runtime_error("PSA key import failed");
    return id;
}
} // namespace

EciesMbedTls::EciesMbedTls() {
    if (psa_crypto_init() != PSA_SUCCESS) throw std::runtime_error("PSA crypto initialisation failed");
}

KeyPair EciesMbedTls::generate_key(KeyType type) {
    const std::size_t n = key_length(type);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family_of(type)));
    psa_set_key_bits(&attributes, n * 8);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    ScopedKey key;
    if (psa_generate_key(&attributes, &key.id) != PSA_SUCCESS) throw std::runtime_error("PSA key generation failed");
    KeyPair pair;
    pair.priv.type = type;
    pair.priv.key.resize(n);
    std::size_t length = 0;
    if (psa_export_key(key.id, pair.priv.key.data(), n, &length) != PSA_SUCCESS || length != n)
        throw std::runtime_error("PSA private key export failed");
    ByteBuffer sec1(1 + 2 * n);
    if (psa_export_public_key(key.id, sec1.data(), sec1.size(), &length) != PSA_SUCCESS || length != sec1.size() || sec1[0] != 0x04)
        throw std::runtime_error("PSA public key export failed");
    pair.pub.type = type;
    pair.pub.compression = KeyCompression::NoCompression;
    pair.pub.x.assign(sec1.begin() + 1, sec1.begin() + 1 + n);
    pair.pub.y.assign(sec1.begin() + 1 + n, sec1.end());
    return pair;
}

std::optional<ByteBuffer> EciesMbedTls::ecdh_x(const PrivateKey& own, const PublicKey& peer) {
    if (own.type != peer.type || peer.compression != KeyCompression::NoCompression) return std::nullopt;
    const std::size_t n = key_length(own.type);
    if (own.key.size() != n || peer.x.size() != n || peer.y.size() != n) return std::nullopt;
    try {
        ScopedKey key;
        key.id = import_raw(PSA_KEY_TYPE_ECC_KEY_PAIR(family_of(own.type)), n * 8, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
                            own.key.data(), own.key.size());
        Uncompressed point;
        point.x = peer.x; point.y = peer.y;
        const ByteBuffer sec1 = ecc::encode_uncompressed(point);
        ByteBuffer secret(n);
        std::size_t length = 0;
        // PSA raw ECDH output is the x coordinate of the shared point (PSA Crypto API 1.1, PSA_ALG_ECDH)
        if (psa_raw_key_agreement(PSA_ALG_ECDH, key.id, sec1.data(), sec1.size(), secret.data(), secret.size(), &length) != PSA_SUCCESS ||
            length != n) return std::nullopt;
        return secret;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

ByteBuffer EciesMbedTls::hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) {
    ScopedKey mac_key;
    mac_key.id = import_raw(PSA_KEY_TYPE_HMAC, 0, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                            key.data(), key.size());
    ByteBuffer out(32);
    std::size_t length = 0;
    if (psa_mac_compute(mac_key.id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data.data(), data.size(), out.data(), out.size(), &length) != PSA_SUCCESS ||
        length != 32) throw std::runtime_error("PSA HMAC failed");
    return out;
}

ByteBuffer EciesMbedTls::random(std::size_t octets) {
    ByteBuffer out(octets);
    if (octets && psa_generate_random(out.data(), out.size()) != PSA_SUCCESS) throw std::runtime_error("PSA random failed");
    return out;
}

bool EciesMbedTls::aes_ccm_encrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                   const ByteBuffer& plaintext, ByteBuffer& out) {
    try {
        ScopedKey aes;
        aes.id = import_raw(PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_CCM, key.data(), key.size());
        out.resize(plaintext.size() + 16);
        std::size_t length = 0;
        if (psa_aead_encrypt(aes.id, PSA_ALG_CCM, nonce.data(), nonce.size(), nullptr, 0, plaintext.data(), plaintext.size(),
                             out.data(), out.size(), &length) != PSA_SUCCESS || length != out.size()) { out.clear(); return false; }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool EciesMbedTls::aes_ccm_decrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                   const ByteBuffer& in, ByteBuffer& plaintext) {
    if (in.size() < 16) return false;
    try {
        ScopedKey aes;
        aes.id = import_raw(PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_DECRYPT, PSA_ALG_CCM, key.data(), key.size());
        plaintext.resize(in.size() - 16);
        std::size_t length = 0;
        if (psa_aead_decrypt(aes.id, PSA_ALG_CCM, nonce.data(), nonce.size(), nullptr, 0, in.data(), in.size(),
                             plaintext.data(), plaintext.size(), &length) != PSA_SUCCESS || length != plaintext.size()) {
            plaintext.clear();
            return false;
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
} // namespace vanetza_idf::pki
