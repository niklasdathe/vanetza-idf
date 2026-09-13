#include <vanetza_idf/ecc.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <iterator>

namespace vanetza_idf::ecc {
using namespace vanetza::security;
namespace {
// Fixed width, no heap: a 384-bit product needs 768 bits before reduction.
using Int = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
    1024, 1024, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked, void>>;

// FIPS 186-4 D.1.2.3 (P-256), RFC 5639 3.4 (brainpoolP256r1) and 3.6 (brainpoolP384r1).
// The host regression compares every constant with OpenSSL's built-in groups.
constexpr CurveParameters curves[] = {
    {KeyType::NistP256, 32,
     "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
     "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"},
    {KeyType::BrainpoolP256r1, 32,
     "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
     "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
     "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"},
    {KeyType::BrainpoolP384r1, 48,
     "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
     "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
     "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"},
};

Int from_hex(const char* hex) { return Int(std::string("0x") + hex); }

Int from_bytes(const vanetza::ByteBuffer& bytes) {
    Int value;
    boost::multiprecision::import_bits(value, bytes.begin(), bytes.end(), 8, true);
    return value;
}

vanetza::ByteBuffer to_bytes(const Int& value, std::size_t octets) {
    vanetza::ByteBuffer out;
    boost::multiprecision::export_bits(value, std::back_inserter(out), 8, true);
    if (out.size() > octets) return {};
    out.insert(out.begin(), octets - out.size(), 0);
    return out;
}
} // namespace

const CurveParameters* curve(KeyType type) {
    for (const auto& c : curves) if (c.type == type) return &c;
    return nullptr;
}

boost::optional<Uncompressed> decompress(KeyType type, const vanetza::ByteBuffer& x_bytes, bool y_odd) {
    const auto* c = curve(type);
    if (!c || x_bytes.size() != c->octets) return boost::none;
    const Int p = from_hex(c->p), a = from_hex(c->a), b = from_hex(c->b);
    const Int x = from_bytes(x_bytes);
    if (x >= p) return boost::none;
    // rhs = x^3 + a*x + b (mod p)
    Int rhs = (x * x) % p;
    rhs = (rhs * x) % p;
    rhs = (rhs + (a * x) % p) % p;
    rhs = (rhs + b) % p;
    // p = 3 (mod 4): sqrt(n) = n^((p+1)/4) (mod p) when n is a quadratic residue.
    Int y = boost::multiprecision::powm(rhs, (p + 1) / 4, p);
    if ((y * y) % p != rhs) return boost::none; // x is not on the curve
    if (static_cast<bool>(y & 1) != y_odd) y = p - y;
    Uncompressed point;
    point.x = x_bytes;
    point.y = to_bytes(y, c->octets);
    if (point.y.empty()) return boost::none;
    return point;
}

vanetza::ByteBuffer encode_uncompressed(const Uncompressed& point) {
    vanetza::ByteBuffer out;
    out.reserve(1 + point.x.size() + point.y.size());
    out.push_back(0x04);
    out.insert(out.end(), point.x.begin(), point.x.end());
    out.insert(out.end(), point.y.begin(), point.y.end());
    return out;
}
} // namespace vanetza_idf::ecc
