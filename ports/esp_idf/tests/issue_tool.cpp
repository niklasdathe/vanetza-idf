// vidf_issue: host-only issuing tool for a lab trust chain under an existing root
// (TS 103 097 V2.2.1 clause 7.2 certificate profiles, IEEE Std 1609.2 clause 5.3.1
// signatures), writing the pool layout the SUT, the test system and the device
// provisioning read (<id>.oer, <id>.vkey raw private scalar, index.lst).
//
//   vidf_issue root      --key KEY --name NAME --id ID --out DIR [--start T] [--years N]
//   vidf_issue authority --issuer CERT.oer --issuer-key KEY --name NAME --id ID --out DIR [--start T] [--years N]
//   vidf_issue ticket    --issuer AA.oer --issuer-key KEY --id ID --out DIR [--start T] [--hours H]
//                        [--permission PSID[:HEXSSP]]... [--region LAT,LON,RADIUS_M]
//   vidf_issue show      CERT.oer                       digest, validity, permissions
//   vidf_issue verify    CERT.oer [ISSUER.oer]          clause 5.3.1 signature check (self-signed without issuer)
//
// KEY is a PEM private key (OpenSSL reads it; an encrypted PEM prompts for the pass
// phrase on the terminal, nothing is echoed or written) or a raw 32-octet .vkey file.
// T is an ISO 8601 UTC instant (2026-09-14T12:00:00Z); the default start is one hour
// before now. Curves: NIST P-256 only. This is issuing for a lab or test environment,
// not a certification authority: no CTL/CRL, no request/response protocol.
#include "test_trust_domain.hpp"
#include "test_backend.hpp"
#include <vanetza_idf/its_time.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;
using vanetza::security::v3::Certificate;

namespace {
ByteBuffer read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + path);
    return ByteBuffer(std::istreambuf_iterator<char>(in), {});
}
void write_file(const std::string& path, const ByteBuffer& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!out) throw std::runtime_error("cannot write " + path);
}
std::string hex(const ByteBuffer& b) {
    static const char* digits = "0123456789ABCDEF";
    std::string s;
    for (auto v : b) { s += digits[v >> 4]; s += digits[v & 15]; }
    return s;
}
ByteBuffer from_hex(const std::string& s) {
    ByteBuffer out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}

// A private key from PEM (pass phrase prompted by OpenSSL) or a raw .vkey scalar; P-256 only.
vidf_test::TrustDomain::KeyMaterial load_key(const std::string& path, Backend& backend) {
    vidf_test::TrustDomain::KeyMaterial material;
    material.priv.type = KeyType::NistP256;
    material.pub.type = KeyType::NistP256;
    material.pub.compression = KeyCompression::NoCompression;
    if (path.size() > 4 && path.compare(path.size() - 4, 4, ".pem") == 0) {
        FILE* fp = std::fopen(path.c_str(), "r");
        if (!fp) throw std::runtime_error("cannot open " + path);
        EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr); // prompts for an encrypted PEM
        std::fclose(fp);
        if (!pkey) throw std::runtime_error("not a readable PEM private key (wrong pass phrase?)");
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
        EVP_PKEY_free(pkey);
        if (!ec || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != NID_X9_62_prime256v1) {
            if (ec) EC_KEY_free(ec);
            throw std::runtime_error("PEM key is not a NIST P-256 key");
        }
        material.priv.key.assign(32, 0);
        BN_bn2binpad(EC_KEY_get0_private_key(ec), material.priv.key.data(), 32);
        EC_KEY_free(ec);
    } else {
        material.priv.key = read_file(path);
        if (material.priv.key.size() != 32) throw std::runtime_error("a raw key file must hold 32 octets");
    }
    // public point from the scalar (OpenSSL, host only), so PEM and raw keys are treated alike
    (void)backend;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* scalar = BN_bin2bn(material.priv.key.data(), 32, nullptr);
    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ec));
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    const bool ok = ec && scalar && point && EC_POINT_mul(EC_KEY_get0_group(ec), point, scalar, nullptr, nullptr, nullptr) == 1 &&
                    EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec), point, x, y, nullptr) == 1;
    if (ok) {
        material.pub.x.assign(32, 0); material.pub.y.assign(32, 0);
        BN_bn2binpad(x, material.pub.x.data(), 32);
        BN_bn2binpad(y, material.pub.y.data(), 32);
    }
    BN_free(x); BN_free(y); EC_POINT_free(point); BN_clear_free(scalar); EC_KEY_free(ec);
    if (!ok) throw std::runtime_error("cannot derive the public key");
    return material;
}

Clock::time_point parse_time(const std::string& iso) {
    int y, mo, d, h, mi, s;
    if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%dZ", &y, &mo, &d, &h, &mi, &s) != 6)
        throw std::runtime_error("time must be YYYY-MM-DDTHH:MM:SSZ");
    // days from civil (Howard Hinnant), proleptic Gregorian, UTC
    y -= mo <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t yoe = y - era * 400;
    const std::int64_t doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t unix_seconds = (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s;
    return Clock::time_point(std::chrono::microseconds(vanetza_idf::its_time::microseconds_since_epoch(unix_seconds)));
}

Clock::time_point now() {
    return Clock::time_point(vanetza_idf::its_time::since_epoch(std::chrono::system_clock::now()));
}

Certificate load_certificate(const std::string& path) {
    Certificate certificate;
    if (!certificate.decode(read_file(path))) throw std::runtime_error("not a COER EtsiTs103097Certificate: " + path);
    return certificate;
}

void store(const std::string& dir, const std::string& id, const Certificate& certificate, const PrivateKey* key) {
    const auto digest = certificate.calculate_digest();
    if (!digest) throw std::runtime_error("certificate has no digest");
    write_file(dir + "/" + id + ".oer", certificate.encode());
    if (key) write_file(dir + "/" + id + ".vkey", key->key);
    std::ofstream index(dir + "/index.lst", std::ios::app);
    index << hex(ByteBuffer(digest->begin(), digest->end())) << ' ' << id << ".oer\n";
    std::printf("%s HashedId8 %s -> %s/%s.oer%s\n", id.c_str(), hex(ByteBuffer(digest->begin(), digest->end())).c_str(),
                dir.c_str(), id.c_str(), key ? " (+ .vkey)" : "");
}

void show(const Certificate& c) {
    const auto digest = c.calculate_digest();
    const auto validity = c.get_start_and_end_validity();
    std::printf("HashedId8      %s\n", digest ? hex(ByteBuffer(digest->begin(), digest->end())).c_str() : "?");
    const auto issuer = c.issuer_digest(); // one optional, one pair of iterators
    std::printf("issuer         %s\n", c.issuer_is_self() ? "self" : issuer ? hex(ByteBuffer(issuer->begin(), issuer->end())).c_str() : "?");
    std::printf("type           %s\n", c.is_ca_certificate() ? "CA (certIssuePermissions)" : c.is_at_certificate() ? "authorization ticket" : "other");
    std::printf("validity       Time32 %u .. %u (Unix %lld .. %lld)\n", unsigned(validity.start_validity), unsigned(validity.end_validity),
                static_cast<long long>(vanetza_idf::its_time::unix_microseconds(static_cast<std::int64_t>(validity.start_validity) * 1000000) / 1000000),
                static_cast<long long>(vanetza_idf::its_time::unix_microseconds(static_cast<std::int64_t>(validity.end_validity) * 1000000) / 1000000));
    if (const auto* permissions = c->toBeSigned.appPermissions) {
        for (int i = 0; i < permissions->list.count; ++i) {
            const auto* entry = permissions->list.array[i];
            std::printf("appPermission  psid %ld", static_cast<long>(entry->psid));
            if (entry->ssp && entry->ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp)
                std::printf(" ssp %s", hex(ByteBuffer(entry->ssp->choice.bitmapSsp.buf, entry->ssp->choice.bitmapSsp.buf + entry->ssp->choice.bitmapSsp.size)).c_str());
            std::printf("\n");
        }
    }
    if (const auto* groups = c->toBeSigned.certIssuePermissions) {
        for (int i = 0; i < groups->list.count; ++i) {
            const auto* group = groups->list.array[i];
            // IEEE Std 1609.2 6.4.28: absent minChainLength = 1, chainLengthRange = 0, eeType = {app}
            const long min = group->minChainLength ? *group->minChainLength : 1;
            const unsigned ee = group->eeType && group->eeType->size ? group->eeType->buf[0] : 0x80;
            std::printf("certIssue      chain length %ld..%s, eeType%s%s:", min,
                        group->chainLengthRange < 0 ? "unbounded" : std::to_string(min + group->chainLengthRange).c_str(),
                        ee & 0x80 ? " app" : "", ee & 0x40 ? " enrol" : "");
            if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all) std::printf(" all");
            else if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_explicit) {
                const auto& ranges = group->subjectPermissions.choice.Explicit.list;
                for (int k = 0; k < ranges.count; ++k) {
                    const auto* range = ranges.array[k];
                    std::printf(" %ld", static_cast<long>(range->psid));
                    if (range->sspRange && range->sspRange->present == Vanetza_Security_SspRange_PR_bitmapSspRange) {
                        const auto& bm = range->sspRange->choice.bitmapSspRange;
                        std::printf("(%s/%s)", hex(ByteBuffer(bm.sspValue.buf, bm.sspValue.buf + bm.sspValue.size)).c_str(),
                                    hex(ByteBuffer(bm.sspBitmask.buf, bm.sspBitmask.buf + bm.sspBitmask.size)).c_str());
                    } else if (range->sspRange && range->sspRange->present == Vanetza_Security_SspRange_PR_opaque) {
                        std::printf("(opaque)");
                    }
                }
            }
            std::printf("\n");
        }
    }
    std::printf("region         %s\n", c->toBeSigned.region ? "restricted" : "none");
}

using Options = std::map<std::string, std::vector<std::string>>;
Options parse(int argc, char** argv, int from) {
    Options options;
    for (int i = from; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--", 0) == 0 && i + 1 < argc) options[arg].push_back(argv[++i]);
        else options["positional"].push_back(arg);
    }
    return options;
}
std::string one(const Options& o, const char* name, const char* fallback = nullptr) {
    auto it = o.find(name);
    if (it != o.end() && !it->second.empty()) return it->second.back();
    if (fallback) return fallback;
    throw std::runtime_error(std::string("missing ") + name);
}
} // namespace

int main(int argc, char** argv) try {
    if (argc < 2) { std::fprintf(stderr, "usage: see the header of issue_tool.cpp\n"); return 2; }
    const std::string command = argv[1];
    vidf_test::TestBackend backend;
    vidf_test::TrustDomain domain {backend, now()}; // the building blocks; its own generated chain is unused
    const Options options = parse(argc, argv, 2);
    if (command == "show") {
        show(load_certificate(one(options, "positional")));
        return 0;
    }
    if (command == "verify") {
        const auto& args = options.at("positional");
        const Certificate subject = load_certificate(args.at(0));
        const Certificate issuer = args.size() > 1 ? load_certificate(args.at(1)) : subject;
        const bool ok = domain.verify_chain_signature(subject, issuer);
        std::printf("%s\n", ok ? "signature verifies" : "signature does NOT verify");
        return ok ? 0 : 1;
    }
    const std::string dir = one(options, "--out");
    const std::string id = one(options, "--id");
    const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : now() - std::chrono::hours(1);
    if (command == "root") {
        const auto key = load_key(one(options, "--key"), backend);
        const auto certificate = domain.issue_root(key.priv, key.pub, one(options, "--name"), start, std::stoul(one(options, "--years", "5")));
        store(dir, id, certificate, nullptr); // the root key stays where it is
        return 0;
    }
    if (command == "authority") {
        vidf_test::Credential issuer;
        issuer.certificate = load_certificate(one(options, "--issuer"));
        issuer.key = load_key(one(options, "--issuer-key"), backend).priv;
        if (!domain.verify_chain_signature(issuer.certificate, issuer.certificate) && issuer.certificate.issuer_is_self())
            throw std::runtime_error("issuer certificate does not verify with itself");
        const auto authority = domain.issue_authority(issuer, one(options, "--name"), start, std::stoul(one(options, "--years", "3")));
        store(dir, id, authority.certificate, &authority.key);
        return 0;
    }
    if (command == "ticket") {
        vidf_test::Credential issuer;
        issuer.certificate = load_certificate(one(options, "--issuer"));
        issuer.key = load_key(one(options, "--issuer-key"), backend).priv;
        vidf_test::TrustDomain::Permissions permissions;
        auto it = options.find("--permission");
        if (it == options.end()) {
            permissions = {{aid::CA, {0x01, 0xff, 0xfc}}, {aid::DEN, {0x01, 0xff, 0xff, 0xff}}, {aid::VRU, {0x01}}, {aid::GN_MGMT, {}}};
        } else {
            for (const auto& spec : it->second) {
                const auto colon = spec.find(':');
                permissions.emplace_back(static_cast<ItsAid>(std::stoul(spec.substr(0, colon))),
                                         colon == std::string::npos ? ByteBuffer {} : from_hex(spec.substr(colon + 1)));
            }
        }
        const unsigned hours = std::stoul(one(options, "--hours", "24"));
        vidf_test::Credential ticket;
        if (options.count("--region")) {
            long lat, lon, radius;
            if (std::sscanf(one(options, "--region").c_str(), "%ld,%ld,%ld", &lat, &lon, &radius) != 3)
                throw std::runtime_error("--region LAT,LON,RADIUS_M in 1/10 microdegrees and metres");
            ticket = domain.issue_ticket(issuer, permissions, start, hours,
                                         vidf_test::TrustDomain::CircularRegion {static_cast<std::int32_t>(lat), static_cast<std::int32_t>(lon), static_cast<std::uint16_t>(radius)});
        } else {
            ticket = domain.issue_ticket(issuer, permissions, start, hours);
        }
        store(dir, id, ticket.certificate, &ticket.key);
        return 0;
    }
    std::fprintf(stderr, "unknown command %s\n", command.c_str());
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "vidf_issue: %s\n", e.what());
    return 1;
}
