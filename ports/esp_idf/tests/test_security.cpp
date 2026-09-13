// Security entity regression: crypto backends against OpenSSL as oracle.
#include "check.hpp"
#include <vanetza_idf/ecc.hpp>
#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/key_type.hpp>
#if VIDF_BACKEND_MBEDTLS
#include <vanetza_idf/backend_mbedtls.hpp>
#endif
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <algorithm>
#include <memory>
#include <string>

using namespace vanetza;
using namespace vanetza::security;
using vidf_test::check;
using vidf_test::hex;

namespace {
const struct { KeyType type; int nid; const char* name; } curves[] = {
    {KeyType::NistP256, NID_X9_62_prime256v1, "NIST P-256"},
    {KeyType::BrainpoolP256r1, NID_brainpoolP256r1, "brainpoolP256r1"},
    {KeyType::BrainpoolP384r1, NID_brainpoolP384r1, "brainpoolP384r1"},
};

std::string upper_hex(const BIGNUM* n, std::size_t octets) {
    ByteBuffer bytes(octets);
    BN_bn2binpad(n, bytes.data(), bytes.size());
    auto s = hex(bytes);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

struct OpenSslKey {
    PrivateKey priv;
    PublicKey pub;
};

// Fresh key on the given curve, straight from OpenSSL: the reference the port is measured against.
OpenSslKey generate(KeyType type, int nid) {
    openssl::Key key(nid);
    openssl::check(EC_KEY_generate_key(key));
    const std::size_t n = key_length(type);
    OpenSslKey out;
    out.priv.type = type;
    out.priv.key.resize(n);
    BN_bn2binpad(EC_KEY_get0_private_key(key), out.priv.key.data(), n);
    openssl::BigNumber x, y;
    openssl::BigNumberContext ctx;
    EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, ctx);
    out.pub.type = type;
    out.pub.compression = KeyCompression::NoCompression;
    out.pub.x.resize(n); out.pub.y.resize(n);
    BN_bn2binpad(x, out.pub.x.data(), n);
    BN_bn2binpad(y, out.pub.y.data(), n);
    return out;
}

PublicKey compressed(const PublicKey& key) {
    PublicKey c = key;
    c.compression = (key.y.back() & 1) ? KeyCompression::Y1 : KeyCompression::Y0;
    c.y.clear();
    return c;
}

void test_curve_constants() {
    for (const auto& curve : curves) {
        openssl::Group group(curve.nid);
        openssl::BigNumber p, a, b;
        openssl::BigNumberContext ctx;
        openssl::check(EC_GROUP_get_curve(group, p, a, b, ctx));
        const auto* params = vanetza_idf::ecc::curve(curve.type);
        check(params != nullptr, "curve parameters known");
        check(upper_hex(p, params->octets) == params->p, "field prime matches OpenSSL");
        check(upper_hex(a, params->octets) == params->a, "coefficient a matches OpenSSL");
        check(upper_hex(b, params->octets) == params->b, "coefficient b matches OpenSSL");
        check(BN_mod_word(p, 4) == 3, "p = 3 (mod 4) so the square root formula applies");
    }
    check(vanetza_idf::ecc::curve(KeyType::Unspecified) == nullptr, "unspecified key type has no curve");
}

void test_decompression() {
    for (const auto& curve : curves) {
        for (int round = 0; round < 4; ++round) {
            const auto key = generate(curve.type, curve.nid);
            const bool odd = key.pub.y.back() & 1;
            auto point = vanetza_idf::ecc::decompress(curve.type, key.pub.x, odd);
            check(point && point->x == key.pub.x && point->y == key.pub.y, "y recovered from x and parity");
            auto other = vanetza_idf::ecc::decompress(curve.type, key.pub.x, !odd);
            check(other && other->y != key.pub.y, "opposite parity gives the negated point");
            // p - y must also lie on the curve according to OpenSSL.
            openssl::Group group(curve.nid);
            openssl::Point p(group);
            openssl::BigNumberContext ctx;
            check(EC_POINT_set_affine_coordinates(group, p, openssl::BigNumber(other->x), openssl::BigNumber(other->y), ctx) == 1 &&
                  EC_POINT_is_on_curve(group, p, ctx) == 1, "negated point is on the curve");
        }
        ByteBuffer short_x(key_length(curve.type) - 1, 0x01);
        check(!vanetza_idf::ecc::decompress(curve.type, short_x, false), "wrong coordinate length rejected");
        ByteBuffer beyond(key_length(curve.type), 0xff); // >= p for every curve here
        check(!vanetza_idf::ecc::decompress(curve.type, beyond, false), "x outside the field rejected");
    }
    // Any decompression result must satisfy the curve equation; a non-residue x must be refused.
    unsigned refused = 0;
    for (std::uint8_t seed = 0; seed < 64; ++seed) {
        ByteBuffer x(32, seed);
        auto point = vanetza_idf::ecc::decompress(KeyType::NistP256, x, false);
        if (!point) { ++refused; continue; }
        openssl::Group group(NID_X9_62_prime256v1);
        openssl::Point p(group);
        openssl::BigNumberContext ctx;
        check(EC_POINT_set_affine_coordinates(group, p, openssl::BigNumber(point->x), openssl::BigNumber(point->y), ctx) == 1 &&
              EC_POINT_is_on_curve(group, p, ctx) == 1, "decompressed point lies on P-256");
    }
    check(refused > 0 && refused < 64, "quadratic non-residues are refused, residues accepted");
}

void round_trip(Backend& signer, Backend& verifier, const char* label) {
    for (const auto& curve : curves) {
        const auto key = generate(curve.type, curve.nid);
        const auto algo = curve.type == KeyType::BrainpoolP384r1 ? HashAlgorithm::SHA384 : HashAlgorithm::SHA256;
        const ByteBuffer message = {'v', 'a', 'n', 'e', 't', 'z', 'a', '-', 'i', 'd', 'f'};
        const auto digest = signer.calculate_hash(algo, message);
        check(digest == verifier.calculate_hash(algo, message), "both backends hash identically");
        check(digest.size() == (algo == HashAlgorithm::SHA384 ? 48u : 32u), "digest length per algorithm");
        const auto signature = signer.sign_digest(key.priv, digest);
        check(signature.type == curve.type && signature.r.size() == key_length(curve.type) &&
              signature.s.size() == key_length(curve.type), "raw r||s signature sizes");
        check(verifier.verify_digest(key.pub, digest, signature), label);
        check(verifier.verify_digest(compressed(key.pub), digest, signature), "verification with compressed public key");
        auto tampered = digest; tampered[0] ^= 0x80;
        check(!verifier.verify_digest(key.pub, tampered, signature), "tampered digest rejected");
        auto bad = signature; bad.s[5] ^= 0x01;
        check(!verifier.verify_digest(key.pub, digest, bad), "tampered signature rejected");
        const auto other = generate(curve.type, curve.nid);
        check(!verifier.verify_digest(other.pub, digest, signature), "wrong public key rejected");
    }
    // Legacy P-256 data signing (v2 profile helpers), cross-verified.
    const auto pair = signer.generate_key_pair();
    const ByteBuffer data(100, 0x5a);
    const auto legacy = signer.sign_data(pair.private_key, data);
    check(verifier.verify_data(pair.public_key, data, legacy), "generated key pair signs and verifies across backends");
    auto data2 = data; data2[7] ^= 1;
    check(!verifier.verify_data(pair.public_key, data2, legacy), "legacy signature bound to data");
    // Compressed point handling of the backend itself against OpenSSL.
    Compressed_Lsb_Y_0 y0; y0.x.assign(pair.public_key.x.begin(), pair.public_key.x.end());
    Compressed_Lsb_Y_1 y1; y1.x = y0.x;
    const EccPoint point = (pair.public_key.y.back() & 1) ? EccPoint(y1) : EccPoint(y0);
    auto expanded = signer.decompress_point(point);
    check(expanded && std::equal(expanded->y.begin(), expanded->y.end(), pair.public_key.y.begin()),
          "backend decompress_point recovers the generated public key");
}
} // namespace

void test_crypto_backends() {
    test_curve_constants();
    test_decompression();
    BackendOpenSsl openssl_backend;
    round_trip(openssl_backend, openssl_backend, "OpenSSL sign/verify per curve");
#if VIDF_BACKEND_MBEDTLS
    vanetza_idf::BackendMbedTls psa;
    round_trip(psa, openssl_backend, "PSA signature verified by OpenSSL");
    round_trip(openssl_backend, psa, "OpenSSL signature verified by PSA");
    round_trip(psa, psa, "PSA sign/verify per curve");
    // Key cache: a second signature with the same key must reuse the imported key, a third key evicts.
    psa.set_key_cache_size(2);
    const auto k1 = generate(KeyType::NistP256, NID_X9_62_prime256v1);
    const auto k2 = generate(KeyType::BrainpoolP256r1, NID_brainpoolP256r1);
    const auto k3 = generate(KeyType::BrainpoolP384r1, NID_brainpoolP384r1);
    const auto d256 = psa.calculate_hash(HashAlgorithm::SHA256, {1, 2, 3});
    const auto d384 = psa.calculate_hash(HashAlgorithm::SHA384, {1, 2, 3});
    for (int i = 0; i < 3; ++i) {
        check(openssl_backend.verify_digest(k1.pub, d256, psa.sign_digest(k1.priv, d256)), "cached key still signs");
        check(openssl_backend.verify_digest(k2.pub, d256, psa.sign_digest(k2.priv, d256)), "second cached key signs");
        check(openssl_backend.verify_digest(k3.pub, d384, psa.sign_digest(k3.priv, d384)), "evicting key signs");
    }
    PrivateKey wrong = k1.priv; wrong.key.pop_back();
    bool threw = false;
    try { psa.sign_digest(wrong, d256); } catch (const std::runtime_error&) { threw = true; }
    check(threw, "malformed private key is refused, not signed");
#endif
}
