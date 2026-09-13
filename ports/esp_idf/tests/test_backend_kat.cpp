// Backend known-answer test: runs on the host against both backends and on a
// device against the PSA backend. The vectors come from pyca/cryptography.
#include "check.hpp"
#include "test_backend.hpp"
#if VIDF_BACKEND_MBEDTLS
#include <vanetza_idf/backend_mbedtls.hpp>
#endif
#include <vanetza_idf/ecc.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/key_type.hpp>
#include <cstring>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;
using vidf_test::check;

namespace {
#include "known_answers.inc"

void run(Backend& backend) {
    static const char text[] = "vanetza-idf device backend";
    const ByteBuffer message(text, text + std::strlen(text));
    for (const auto& kat : known_answers) {
        const std::size_t n = kat.n;
        PrivateKey priv {kat.type, ByteBuffer(kat.d, kat.d + n)};
        PublicKey pub;
        pub.type = kat.type; pub.compression = KeyCompression::NoCompression;
        pub.x.assign(kat.x, kat.x + n); pub.y.assign(kat.y, kat.y + n);
        const ByteBuffer digest(kat.digest, kat.digest + n);
        Signature signature;
        signature.type = kat.type;
        signature.r.assign(kat.sig, kat.sig + n);
        signature.s.assign(kat.sig + n, kat.sig + 2 * n);
        check(backend.calculate_hash(n == 48 ? HashAlgorithm::SHA384 : HashAlgorithm::SHA256, message) == digest,
              "hash of the message matches the independent implementation");
        check(backend.verify_digest(pub, digest, signature), "independent ECDSA signature verifies");
        PublicKey compressed = pub;
        compressed.compression = (pub.y.back() & 1) ? KeyCompression::Y1 : KeyCompression::Y0;
        compressed.y.clear();
        check(backend.verify_digest(compressed, digest, signature), "verifies with the compressed public key");
        auto point = vanetza_idf::ecc::decompress(kat.type, pub.x, pub.y.back() & 1);
        check(point && point->y == pub.y, "decompression reproduces the independent y coordinate");
        ByteBuffer wrong = digest; wrong[3] ^= 0x10;
        check(!backend.verify_digest(pub, wrong, signature), "tampered digest rejected");
        Signature bad = signature; bad.r[0] ^= 0x01;
        check(!backend.verify_digest(pub, digest, bad), "tampered signature rejected");
        const auto own = backend.sign_digest(priv, digest);
        check(own.r.size() == n && own.s.size() == n && backend.verify_digest(pub, digest, own),
              "own signature with the independent private key verifies under its public key");
    }
    const auto pair = backend.generate_key_pair();
    const auto legacy = backend.sign_data(pair.private_key, message);
    check(backend.verify_data(pair.public_key, message, legacy), "generated key pair round trip");
}
} // namespace

void test_crypto_backend_known_answers() {
    vidf_test::TestBackend backend;
    run(backend);
#if VIDF_BACKEND_OPENSSL && VIDF_BACKEND_MBEDTLS
    vanetza_idf::BackendMbedTls psa;
    run(psa);
#endif
}
