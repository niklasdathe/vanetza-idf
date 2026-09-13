#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/key_type.hpp>
#include <boost/optional/optional.hpp>
#include <cstddef>

namespace vanetza_idf::ecc {

/** Short Weierstrass domain parameters y^2 = x^3 + a*x + b (mod p), big-endian octets.
 * NIST P-256 (FIPS 186-4 D.1.2.3), brainpoolP256r1 and brainpoolP384r1 (RFC 5639
 * clause 3.4/3.6): the three curves TS 103 097 V2.2.1 clause 6 admits for
 * verification keys (IEEE Std 1609.2 clause 6.4.36 PublicVerificationKey).
 * All three primes satisfy p = 3 (mod 4).
 */
struct CurveParameters {
    vanetza::security::KeyType type;
    std::size_t octets; // field element length
    const char* p;
    const char* a;
    const char* b;
};

/** Domain parameters for a key type, nullptr for KeyType::Unspecified. */
const CurveParameters* curve(vanetza::security::KeyType);

/** Recover an affine point from its x coordinate and the parity of y.
 * IEEE Std 1609.2 clause 6.3.23 EccP256CurvePoint / 6.3.24 EccP384CurvePoint
 * compressed-y-0 / compressed-y-1 forms (SEC 1 clause 2.3.4). Pure integer
 * arithmetic (Boost.Multiprecision), so it is independent of the crypto backend.
 * \return uncompressed point, or none if x has the wrong length or is not on the curve
 */
boost::optional<vanetza::security::Uncompressed>
decompress(vanetza::security::KeyType, const vanetza::ByteBuffer& x, bool y_odd);

/** SEC 1 clause 2.3.3 octet-string point encoding 0x04 || X || Y. */
vanetza::ByteBuffer encode_uncompressed(const vanetza::security::Uncompressed&);

} // namespace vanetza_idf::ecc
