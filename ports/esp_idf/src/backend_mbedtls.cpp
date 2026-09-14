#include <vanetza_idf/backend_mbedtls.hpp>
#include <vanetza_idf/ecc.hpp>
#include <vanetza/security/sha.hpp>
#include <psa/crypto.h>
#include <algorithm>
#include <deque>
#include <stdexcept>

namespace vanetza_idf {
using namespace vanetza::security;
namespace {

psa_ecc_family_t family(KeyType type) {
    switch (type) {
        case KeyType::NistP256: return PSA_ECC_FAMILY_SECP_R1;
        case KeyType::BrainpoolP256r1:
        case KeyType::BrainpoolP384r1: return PSA_ECC_FAMILY_BRAINPOOL_P_R1;
        default: throw std::runtime_error("unsupported key type");
    }
}

std::size_t curve_bits(KeyType type) { return key_length(type) * 8; }

struct ScopedKey {
    mbedtls_svc_key_id_t id = 0;
    ~ScopedKey() { if (id) psa_destroy_key(id); }
};

// SEC 1 uncompressed encoding of a generic public key, recovering y when compressed.
vanetza::ByteBuffer public_key_octets(const PublicKey& key) {
    Uncompressed point;
    switch (key.compression) {
        case KeyCompression::NoCompression:
            point.x = key.x; point.y = key.y;
            break;
        case KeyCompression::Y0:
        case KeyCompression::Y1: {
            auto recovered = ecc::decompress(key.type, key.x, key.compression == KeyCompression::Y1);
            if (!recovered) throw std::runtime_error("public key is not on the curve");
            point = std::move(*recovered);
            break;
        }
        default: throw std::runtime_error("unsupported point compression");
    }
    if (point.x.size() != key_length(key.type) || point.y.size() != key_length(key.type))
        throw std::runtime_error("public key coordinate length");
    return ecc::encode_uncompressed(point);
}

// The digest handed in is the SHA-256/SHA-384 output IEEE Std 1609.2 clause 5.3.1 prescribes
// for the curve, so the operation names that hash: implementations that accelerate ECDSA
// (ESP-IDF's PSA driver for the ESP32-C5 ECDSA peripheral, CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY)
// only take PSA_ALG_ECDSA(PSA_ALG_SHA_256/384), never PSA_ALG_ECDSA_ANY, which falls back to
// software. Keys are imported with the wildcard policy so either form is permitted.
psa_algorithm_t ecdsa_algorithm(std::size_t digest_octets) {
    switch (digest_octets) {
        case 32: return PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        case 48: return PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        default: return PSA_ALG_ECDSA_ANY;
    }
}

mbedtls_svc_key_id_t import_public(KeyType type, const vanetza::ByteBuffer& sec1) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(family(type)));
    psa_set_key_bits(&attributes, curve_bits(type));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    mbedtls_svc_key_id_t id = 0;
    if (psa_import_key(&attributes, sec1.data(), sec1.size(), &id) != PSA_SUCCESS)
        throw std::runtime_error("PSA public key import failed");
    return id;
}

vanetza::ByteBuffer raw_signature(mbedtls_svc_key_id_t key, KeyType type, const vanetza::ByteBuffer& digest) {
    vanetza::ByteBuffer signature(2 * key_length(type));
    std::size_t length = 0;
    const auto status = psa_sign_hash(key, ecdsa_algorithm(digest.size()), digest.data(), digest.size(),
                                      signature.data(), signature.size(), &length);
    if (status != PSA_SUCCESS || length != signature.size()) throw std::runtime_error("PSA ECDSA signing failed");
    return signature;
}

bool verify_raw(KeyType type, const vanetza::ByteBuffer& sec1, const vanetza::ByteBuffer& digest,
                const vanetza::ByteBuffer& r, const vanetza::ByteBuffer& s) {
    const auto n = key_length(type);
    if (r.size() != n || s.size() != n) return false;
    vanetza::ByteBuffer signature;
    signature.reserve(2 * n);
    signature.insert(signature.end(), r.begin(), r.end());
    signature.insert(signature.end(), s.begin(), s.end());
    ScopedKey key;
    try { key.id = import_public(type, sec1); } catch (const std::runtime_error&) { return false; }
    return psa_verify_hash(key.id, ecdsa_algorithm(digest.size()), digest.data(), digest.size(),
                           signature.data(), signature.size()) == PSA_SUCCESS;
}
} // namespace

class BackendMbedTls::Impl {
public:
    struct Entry { KeyType type; vanetza::ByteBuffer secret; mbedtls_svc_key_id_t id; };
    std::deque<Entry> cache;
    std::size_t capacity = 4;

    ~Impl() { for (auto& entry : cache) psa_destroy_key(entry.id); }

    mbedtls_svc_key_id_t signing_key(KeyType type, const vanetza::ByteBuffer& secret) {
        if (secret.size() != key_length(type)) throw std::runtime_error("private key length");
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            if (it->type == type && it->secret == secret) {
                Entry hit = std::move(*it);
                cache.erase(it);
                cache.push_front(std::move(hit)); // most recently used first
                return cache.front().id;
            }
        }
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family(type)));
        psa_set_key_bits(&attributes, curve_bits(type));
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
        mbedtls_svc_key_id_t id = 0;
        if (psa_import_key(&attributes, secret.data(), secret.size(), &id) != PSA_SUCCESS)
            throw std::runtime_error("PSA private key import failed");
        while (cache.size() >= capacity) {
            psa_destroy_key(cache.back().id);
            cache.pop_back();
        }
        cache.push_front(Entry {type, secret, id});
        return id;
    }
};

BackendMbedTls::BackendMbedTls() : impl_(std::make_unique<Impl>()) {
    if (psa_crypto_init() != PSA_SUCCESS) throw std::runtime_error("PSA crypto initialisation failed");
}
BackendMbedTls::~BackendMbedTls() = default;
void BackendMbedTls::set_key_cache_size(std::size_t size) { impl_->capacity = std::max<std::size_t>(1, size); }

EcdsaSignature BackendMbedTls::sign_data(const ecdsa256::PrivateKey& key, const vanetza::ByteBuffer& data) {
    const auto digest = calculate_sha256_digest(data.data(), data.size());
    const vanetza::ByteBuffer secret(key.key.begin(), key.key.end());
    const auto id = impl_->signing_key(KeyType::NistP256, secret);
    auto raw = raw_signature(id, KeyType::NistP256, vanetza::ByteBuffer(digest.begin(), digest.end()));
    EcdsaSignature signature;
    X_Coordinate_Only r;
    r.x.assign(raw.begin(), raw.begin() + 32);
    signature.R = std::move(r);
    signature.s.assign(raw.begin() + 32, raw.end());
    return signature;
}

Signature BackendMbedTls::sign_digest(const PrivateKey& key, const vanetza::ByteBuffer& digest) {
    const auto id = impl_->signing_key(key.type, key.key);
    auto raw = raw_signature(id, key.type, digest);
    const auto n = key_length(key.type);
    Signature signature;
    signature.type = key.type;
    signature.r.assign(raw.begin(), raw.begin() + n);
    signature.s.assign(raw.begin() + n, raw.end());
    return signature;
}

bool BackendMbedTls::verify_data(const ecdsa256::PublicKey& key, const vanetza::ByteBuffer& data,
                                 const EcdsaSignature& signature) {
    const auto digest = calculate_sha256_digest(data.data(), data.size());
    Uncompressed point;
    point.x.assign(key.x.begin(), key.x.end());
    point.y.assign(key.y.begin(), key.y.end());
    return verify_raw(KeyType::NistP256, ecc::encode_uncompressed(point),
                      vanetza::ByteBuffer(digest.begin(), digest.end()),
                      convert_for_signing(signature.R), signature.s);
}

bool BackendMbedTls::verify_digest(const PublicKey& key, const vanetza::ByteBuffer& digest, const Signature& signature) {
    if (key.type != signature.type) return false;
    try {
        return verify_raw(key.type, public_key_octets(key), digest, signature.r, signature.s);
    } catch (const std::runtime_error&) {
        return false;
    }
}

boost::optional<Uncompressed> BackendMbedTls::decompress_point(const EccPoint& ecc_point) {
    struct Visitor : boost::static_visitor<boost::optional<Uncompressed>> {
        boost::optional<Uncompressed> operator()(const X_Coordinate_Only&) const { return boost::none; }
        boost::optional<Uncompressed> operator()(const Compressed_Lsb_Y_0& p) const {
            return ecc::decompress(KeyType::NistP256, p.x, false);
        }
        boost::optional<Uncompressed> operator()(const Compressed_Lsb_Y_1& p) const {
            return ecc::decompress(KeyType::NistP256, p.x, true);
        }
        boost::optional<Uncompressed> operator()(const Uncompressed& p) const { return p; }
    };
    Visitor visitor;
    return boost::apply_visitor(visitor, ecc_point);
}

vanetza::ByteBuffer BackendMbedTls::calculate_hash(HashAlgorithm algorithm, const vanetza::ByteBuffer& data) {
    psa_algorithm_t alg;
    std::size_t size;
    switch (algorithm) {
        case HashAlgorithm::SHA256: alg = PSA_ALG_SHA_256; size = 32; break;
        case HashAlgorithm::SHA384: alg = PSA_ALG_SHA_384; size = 48; break;
        default: return {};
    }
    vanetza::ByteBuffer digest(size);
    std::size_t written = 0;
    if (psa_hash_compute(alg, data.data(), data.size(), digest.data(), digest.size(), &written) != PSA_SUCCESS ||
        written != size) throw std::runtime_error("PSA hash failed");
    return digest;
}

ecdsa256::KeyPair BackendMbedTls::generate_key_pair() {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
    ScopedKey key;
    if (psa_generate_key(&attributes, &key.id) != PSA_SUCCESS) throw std::runtime_error("PSA key generation failed");
    ecdsa256::KeyPair pair;
    std::size_t length = 0;
    if (psa_export_key(key.id, pair.private_key.key.data(), pair.private_key.key.size(), &length) != PSA_SUCCESS ||
        length != pair.private_key.key.size()) throw std::runtime_error("PSA private key export failed");
    std::array<std::uint8_t, 65> sec1 {};
    if (psa_export_public_key(key.id, sec1.data(), sec1.size(), &length) != PSA_SUCCESS || length != sec1.size() ||
        sec1[0] != 0x04) throw std::runtime_error("PSA public key export failed");
    std::copy(sec1.begin() + 1, sec1.begin() + 33, pair.public_key.x.begin());
    std::copy(sec1.begin() + 33, sec1.end(), pair.public_key.y.begin());
    return pair;
}
} // namespace vanetza_idf
