#include <vanetza_idf/ecies_openssl.hpp>
#include <vanetza_idf/ecc.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <memory>
#include <stdexcept>

namespace vanetza_idf::pki {
using namespace vanetza::security;
namespace {
int nid_of(KeyType type) {
    switch (type) {
        case KeyType::NistP256: return NID_X9_62_prime256v1;
        case KeyType::BrainpoolP256r1: return NID_brainpoolP256r1;
        case KeyType::BrainpoolP384r1: return NID_brainpoolP384r1;
        default: return NID_undef;
    }
}
struct CipherContext {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~CipherContext() { EVP_CIPHER_CTX_free(ctx); }
};
} // namespace

KeyPair EciesOpenSsl::generate_key(KeyType type) {
    openssl::Key key(nid_of(type));
    openssl::check(EC_KEY_generate_key(key));
    const std::size_t n = key_length(type);
    KeyPair pair;
    pair.priv.type = type;
    pair.priv.key.resize(n);
    BN_bn2binpad(EC_KEY_get0_private_key(key), pair.priv.key.data(), n);
    openssl::BigNumber x, y;
    openssl::BigNumberContext ctx;
    openssl::check(EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, ctx));
    pair.pub.type = type;
    pair.pub.compression = KeyCompression::NoCompression;
    pair.pub.x.resize(n); pair.pub.y.resize(n);
    BN_bn2binpad(x, pair.pub.x.data(), n);
    BN_bn2binpad(y, pair.pub.y.data(), n);
    return pair;
}

std::optional<ByteBuffer> EciesOpenSsl::ecdh_x(const PrivateKey& own, const PublicKey& peer) {
    if (own.type != peer.type || peer.compression != KeyCompression::NoCompression) return std::nullopt;
    try {
        openssl::Key key(nid_of(own.type));
        openssl::BigNumber d(own.key);
        openssl::check(EC_KEY_set_private_key(key, d));
        openssl::Group group(nid_of(peer.type));
        openssl::Point point(group);
        openssl::BigNumberContext ctx;
        openssl::check(EC_POINT_set_affine_coordinates(group, point, openssl::BigNumber(peer.x), openssl::BigNumber(peer.y), ctx));
        openssl::check(EC_POINT_is_on_curve(group, point, ctx) == 1);
        ByteBuffer secret(key_length(own.type));
        // no KDF here: the raw x coordinate is the ECIES shared secret input to KDF2
        const int written = ECDH_compute_key(secret.data(), secret.size(), point, key, nullptr);
        if (written != static_cast<int>(secret.size())) return std::nullopt;
        return secret;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

ByteBuffer EciesOpenSsl::hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) {
    ByteBuffer out(32);
    unsigned length = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &length) ||
        length != 32) throw std::runtime_error("HMAC-SHA256 failed");
    return out;
}

ByteBuffer EciesOpenSsl::random(std::size_t octets) {
    ByteBuffer out(octets);
    if (octets && RAND_bytes(out.data(), static_cast<int>(octets)) != 1) throw std::runtime_error("RAND_bytes failed");
    return out;
}

bool EciesOpenSsl::aes_ccm_encrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                   const ByteBuffer& plaintext, ByteBuffer& out) {
    CipherContext c;
    if (!c.ctx) return false;
    int length = 0;
    if (EVP_EncryptInit_ex(c.ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_CCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_CCM_SET_TAG, 16, nullptr) != 1 ||
        EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(c.ctx, nullptr, &length, nullptr, static_cast<int>(plaintext.size())) != 1) return false;
    out.resize(plaintext.size() + 16);
    if (EVP_EncryptUpdate(c.ctx, out.data(), &length, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        length != static_cast<int>(plaintext.size())) return false;
    int final_length = 0;
    if (EVP_EncryptFinal_ex(c.ctx, out.data() + length, &final_length) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_CCM_GET_TAG, 16, out.data() + plaintext.size()) != 1) return false;
    return true;
}

bool EciesOpenSsl::aes_ccm_decrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                   const ByteBuffer& in, ByteBuffer& plaintext) {
    if (in.size() < 16) return false;
    const std::size_t payload = in.size() - 16;
    CipherContext c;
    if (!c.ctx) return false;
    int length = 0;
    if (EVP_DecryptInit_ex(c.ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_CCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_CCM_SET_TAG, 16, const_cast<std::uint8_t*>(in.data() + payload)) != 1 ||
        EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(c.ctx, nullptr, &length, nullptr, static_cast<int>(payload)) != 1) return false;
    plaintext.resize(payload);
    // CCM verifies the tag inside this update; a mismatch returns 0
    if (EVP_DecryptUpdate(c.ctx, plaintext.data(), &length, in.data(), static_cast<int>(payload)) != 1 ||
        length != static_cast<int>(payload)) { plaintext.clear(); return false; }
    return true;
}
} // namespace vanetza_idf::pki
