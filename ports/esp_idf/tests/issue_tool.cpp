// vidf_issue: host-only issuing tool for a lab trust chain under an existing root
// (TS 103 097 V2.2.1 clause 7.2 certificate profiles, IEEE Std 1609.2 clause 5.3.1
// signatures), writing the pool layout the SUT, the test system and the device
// provisioning read (<id>.oer, <id>.vkey raw private scalar, index.lst).
//
//   vidf_issue root      --key KEY --name NAME --id ID --out DIR [--start T] [--years N] [--like ROOT.oer]
//   vidf_issue authority --issuer CERT.oer --issuer-key KEY --name NAME --id ID --out DIR [--start T] [--years N]
//                                                       also writes <id>.ekey: the private half of the ECIES
//                                                       encryption key embedded in the certificate (clause 7.2.4)
//   vidf_issue ticket    --issuer AA.oer --issuer-key KEY --id ID --out DIR [--start T] [--hours H]
//                        [--permission PSID[:HEXSSP]]... [--region LAT,LON,RADIUS_M] [--root ROOT.oer]
//   vidf_issue show      CERT.oer                       digest, validity, permissions, region
//   vidf_issue verify    CERT.oer [ISSUER.oer [ROOT.oer]]  clause 5.3.1 signatures, IEEE 1609.2 clause 5.1.2
//                                                       permission/region/time consistency of the chain
//   vidf_issue ctl       --issuer ROOT.oer --issuer-key KEY --out FILE [--sequence N] [--next-update T]
//                        [--aa CERT.oer[=URL]]... [--ea CERT.oer[=URL]]... [--dc URL[=HASHEDID8,...]]...
//                                                       TS 102 941 clause 6.3.2/6.3.4 RcaCertificateTrustListMessage (FullCtl)
//   vidf_issue crl       --issuer ROOT.oer --issuer-key KEY --out FILE [--next-update T] [--revoke HASHEDID8]...
//                                                       TS 102 941 clause 6.3.3 CertificateRevocationListMessage
//   vidf_issue inspect   FILE --root ROOT.oer            read a CTL or CRL back as an ITS-S would (clause 6.3.6)
//
// TS 102 941 clause 6.2.3 enrolment/authorization, offline steps around a real HTTP
// transport (ports/esp_idf/tools/local_pki.py / pki_client.py carry the bytes; nothing
// here touches a network):
//   vidf_issue enrol-request     --ea EA.oer --canonical-key KEY --its-id ID [--permission PSID[:HEXSSP]]...
//                                --out REQUEST.bin --context CONTEXT.bin --out-key EC.vkey [--start T]
//   vidf_issue enrol-response    --ea EA.oer --context CONTEXT.bin --response RESPONSE.bin --out EC.oer
//   vidf_issue authorize-request --ea EA.oer --aa AA.oer --ec EC.oer --ec-key EC.vkey
//                                [--permission PSID[:HEXSSP]]... [--hours H] [--start T]
//                                --out REQUEST.bin --context CONTEXT.bin --out-key AT.vkey
//   vidf_issue authorize-response --aa AA.oer --context CONTEXT.bin --response RESPONSE.bin --out AT.oer
//   vidf_issue ea-respond  --ea EA.oer --ea-key KEY --ea-enc-key EA.ekey --request REQUEST.bin --out RESPONSE.bin
//                          --dir DIR (--canonical-key KEY | --current-ec EC.oer) [--name NAME] [--years N] [--deny CODE]
//                                                       issues an EC and stores it under DIR (index.lst) for aa-respond
//   vidf_issue aa-respond  --aa AA.oer --aa-key KEY --aa-enc-key AA.ekey
//                          --ea EA.oer --ea-key KEY --ea-enc-key EA.ekey
//                          --ec-dir DIR --request REQUEST.bin --out RESPONSE.bin [--hours H] [--deny CODE]
//                                                       validates entitlement (clause 6.2.3.3, "AA <-> EA")
//                                                       against every EC ea-respond stored under --ec-dir
// ea-respond/aa-respond are a lab authority, not a production PKI: --canonical-key is the
// same private key file the enrolling station used (a real EA only ever sees the public
// half, registered out of band; a lab tool run on the same machine is handed the file
// directly), and there is no replay protection, no butterfly keys, no revocation.
//
// KEY is a PEM private key (OpenSSL reads it; an encrypted PEM prompts for the pass
// phrase on the terminal, nothing is echoed or written) or a raw 32-octet .vkey file.
// T is an ISO 8601 UTC instant (2026-09-14T12:00:00Z); the default start is one hour
// before now, never before the issuer's own start. An authority's issuing permissions
// and region are derived from its issuer (IEEE Std 1609.2 6.4.28/6.4.17); a ticket
// inherits the issuer's region unless --region names a circle. --like copies the
// permissions and region of an existing root into a lab root with a throwaway key (a
// rehearsal twin of a real root). Nothing is written when the result would not verify
// as a consistent chain (the library's own rules).
// Curves: NIST P-256 only. This is issuing for a lab or test environment, not a
// certification authority.
#include "pki_authority.hpp"
#include "test_trust_domain.hpp"
#include "test_backend.hpp"
#include <vanetza_idf/its_time.hpp>
#include <vanetza_idf/security.hpp>
#include <vanetza_idf/pki.hpp>
#if VIDF_BACKEND_OPENSSL
#include <vanetza_idf/ecies_openssl.hpp>
#endif
#if VIDF_BACKEND_MBEDTLS
#include <vanetza_idf/ecies_mbedtls.hpp>
#endif
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
#include <optional>
#include <sstream>
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
std::string digest_hex(const Certificate& c) { // one optional, one pair of iterators
    const auto digest = c.calculate_digest();
    return digest ? hex(ByteBuffer(digest->begin(), digest->end())) : std::string("?");
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
    if (const auto* region = c->toBeSigned.region) {
        switch (region->present) {
            case Vanetza_Security_GeographicRegion_PR_circularRegion:
                std::printf("region         circle %ld,%ld r=%ld m\n", static_cast<long>(region->choice.circularRegion.center.latitude),
                            static_cast<long>(region->choice.circularRegion.center.longitude), static_cast<long>(region->choice.circularRegion.radius));
                break;
            case Vanetza_Security_GeographicRegion_PR_identifiedRegion: {
                std::printf("region         identified (UN M49 country codes):");
                const auto& list = region->choice.identifiedRegion.list;
                for (int i = 0; i < list.count; ++i) {
                    const auto* entry = list.array[i];
                    if (!entry) continue;
                    if (entry->present == Vanetza_Security_IdentifiedRegion_PR_countryOnly) std::printf(" %ld", static_cast<long>(entry->choice.countryOnly));
                    else if (entry->present == Vanetza_Security_IdentifiedRegion_PR_countryAndRegions) std::printf(" %ld(regions)", static_cast<long>(entry->choice.countryAndRegions.countryOnly));
                    else if (entry->present == Vanetza_Security_IdentifiedRegion_PR_countryAndSubregions) std::printf(" %ld(subregions)", static_cast<long>(entry->choice.countryAndSubregions.country));
                    else std::printf(" ?");
                }
                std::printf("\n");
                break;
            }
            default:
                std::printf("region         restricted (rectangular/polygonal)\n");
        }
    } else {
        std::printf("region         none\n");
    }
}

// The chain the library would verify: signatures, permissions, regions and validity nesting.
// chain[0] is the subject, then its issuer and so on. Prints each finding; false on any.
bool chain_ok(vidf_test::TrustDomain& domain, const std::vector<const Certificate*>& chain) {
    bool ok = true;
    for (std::size_t i = 0; i < chain.size(); ++i) {
        const Certificate& subject = *chain[i];
        const Certificate& issuer = i + 1 < chain.size() ? *chain[i + 1] : subject;
        if (i + 1 == chain.size() && !subject.issuer_is_self()) { std::printf("  chain ends at a certificate that is not self-signed (issuer not given)\n"); continue; }
        const bool signature = domain.verify_chain_signature(subject, issuer);
        std::printf("  signature of %zu: %s\n", i, signature ? "verifies" : "does NOT verify");
        ok = ok && signature;
        if (i + 1 < chain.size()) {
            const auto s_valid = subject.get_start_and_end_validity();
            const auto i_valid = issuer.get_start_and_end_validity();
            const bool time = i_valid.start_validity <= s_valid.start_validity && i_valid.end_validity >= s_valid.end_validity;
            std::printf("  validity of %zu inside %zu: %s\n", i, i + 1, time ? "yes" : "NO (IEEE 1609.2: a certificate is not valid outside its issuer's validity)");
            const bool region = vanetza_idf::security::region_within(subject, issuer, true);
            std::printf("  region of %zu inside %zu: %s\n", i, i + 1, region ? "yes (a geometric region under an identified one is accepted by policy only)" : "NO");
            ok = ok && time && region;
        }
    }
    if (chain.size() > 1) {
        const bool permissions = vanetza_idf::security::chain_permissions_consistent(chain);
        std::printf("  permissions consistent along the chain (IEEE 1609.2 5.1.2): %s\n", permissions ? "yes" : "NO");
        ok = ok && permissions;
    }
    return ok;
}

// default start: an hour ago, but never before the issuer became valid
Clock::time_point default_start(const Certificate* issuer) {
    Clock::time_point start = now() - std::chrono::hours(1);
    if (issuer) {
        const auto issuer_start = Clock::time_point(std::chrono::seconds(issuer->get_start_and_end_validity().start_validity));
        if (issuer_start > start) {
            start = issuer_start;
            std::printf("note: the issuer is valid from Time32 %u only; the start is set to that instant\n",
                        static_cast<unsigned>(issuer->get_start_and_end_validity().start_validity));
        }
    }
    return start;
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

// --permission PSID[:HEXSSP]..., or a fallback set when none is given.
vidf_test::TrustDomain::Permissions parse_permissions(const Options& options, vidf_test::TrustDomain::Permissions fallback) {
    auto it = options.find("--permission");
    if (it == options.end()) return fallback;
    vidf_test::TrustDomain::Permissions permissions;
    for (const auto& spec : it->second) {
        const auto colon = spec.find(':');
        permissions.emplace_back(static_cast<ItsAid>(std::stoul(spec.substr(0, colon))),
                                 colon == std::string::npos ? ByteBuffer {} : from_hex(spec.substr(colon + 1)));
    }
    return permissions;
}

// The 32-octet RequestContext (clause 6.2.3.2.1/6.2.3.3.1: the AES key a response is
// encrypted with, and the 16-octet request hash it must echo), carried between the
// *-request and *-response steps as a small file.
void write_context(const std::string& path, const vanetza_idf::pki::RequestContext& context) {
    ByteBuffer bytes(context.aes_key.begin(), context.aes_key.end());
    bytes.insert(bytes.end(), context.request_hash.begin(), context.request_hash.end());
    write_file(path, bytes);
}
vanetza_idf::pki::RequestContext read_context(const std::string& path) {
    const auto bytes = read_file(path);
    if (bytes.size() != 32) throw std::runtime_error("a context file must hold 32 octets (16 AES key + 16 request hash)");
    vanetza_idf::pki::RequestContext context;
    std::copy(bytes.begin(), bytes.begin() + 16, context.aes_key.begin());
    std::copy(bytes.begin() + 16, bytes.end(), context.request_hash.begin());
    return context;
}

#if VIDF_BACKEND_OPENSSL
using ToolEcies = vanetza_idf::pki::EciesOpenSsl;
#else
using ToolEcies = vanetza_idf::pki::EciesMbedTls;
#endif
} // namespace

int main(int argc, char** argv) try {
    if (argc < 2) { std::fprintf(stderr, "usage: see the header of issue_tool.cpp\n"); return 2; }
    const std::string command = argv[1];
    vidf_test::TestBackend backend;
    ToolEcies ecies;
    vidf_test::TrustDomain domain {backend, now()}; // the building blocks; its own generated chain is unused
    const Options options = parse(argc, argv, 2);
    if (command == "show") {
        show(load_certificate(one(options, "positional")));
        return 0;
    }
    if (command == "inspect") {
        const Certificate rca = load_certificate(one(options, "--root"));
        const ByteBuffer message = read_file(one(options, "positional"));
        if (const auto ctl = vanetza_idf::pki::parse_rca_ctl(backend, message, rca)) {
            std::printf("RCA CTL of %s: %s, sequence %u, nextUpdate Time32 %u\n", digest_hex(rca).c_str(),
                        ctl->full ? "full" : "delta", unsigned(ctl->sequence), unsigned(ctl->next_update));
            for (const auto& ea : ctl->ea) std::printf("  ea  %s\n", digest_hex(ea).c_str());
            for (const auto& aa : ctl->aa) std::printf("  aa  %s\n", digest_hex(aa).c_str());
            for (const auto& dc : ctl->dc) {
                std::printf("  dc  %s:", dc.url.c_str());
                for (const auto& id : dc.certificates) std::printf(" %s", hex(ByteBuffer(id.begin(), id.end())).c_str());
                std::printf("\n");
            }
            for (const auto& id : ctl->deleted) std::printf("  delete %s\n", hex(ByteBuffer(id.begin(), id.end())).c_str());
            return 0;
        }
        if (const auto crl = vanetza_idf::pki::parse_crl(backend, message, rca)) {
            std::printf("CRL of %s: thisUpdate Time32 %u, nextUpdate Time32 %u, %zu revoked\n",
                        digest_hex(rca).c_str(),
                        unsigned(crl->this_update), unsigned(crl->next_update), crl->revoked.size());
            for (const auto& id : crl->revoked) std::printf("  revoked %s\n", hex(ByteBuffer(id.begin(), id.end())).c_str());
            return 0;
        }
        std::printf("neither a CTL nor a CRL signed by that root\n");
        return 1;
    }
    if (command == "ctl" || command == "crl") {
        const Certificate rca = load_certificate(one(options, "--issuer"));
        const auto key = load_key(one(options, "--issuer-key"), backend).priv;
        const std::string out = one(options, "--out");
        const Clock::time_point at = now();
        const auto next_update = options.count("--next-update")
            ? static_cast<vanetza_idf::pki::Time32>(std::chrono::duration_cast<std::chrono::seconds>(parse_time(one(options, "--next-update")).time_since_epoch()).count())
            : static_cast<vanetza_idf::pki::Time32>(std::chrono::duration_cast<std::chrono::seconds>(at.time_since_epoch()).count() + 7 * 86400);
        std::optional<ByteBuffer> message;
        if (command == "ctl") {
            vanetza_idf::pki::TrustListEntries entries;
            const auto authority = [&](const std::string& spec) {
                const auto eq = spec.find('=');
                vanetza_idf::pki::TrustListEntries::Authority a;
                a.certificate = read_file(spec.substr(0, eq));
                if (eq != std::string::npos) a.access_point = spec.substr(eq + 1);
                return a;
            };
            if (auto it = options.find("--ea"); it != options.end()) for (const auto& spec : it->second) entries.ea.push_back(authority(spec));
            if (auto it = options.find("--aa"); it != options.end()) for (const auto& spec : it->second) entries.aa.push_back(authority(spec));
            if (auto it = options.find("--dc"); it != options.end()) {
                for (const auto& spec : it->second) {
                    vanetza_idf::pki::TrustListEntries::DistributionCentre dc;
                    const auto eq = spec.find('=');
                    dc.url = spec.substr(0, eq);
                    std::string ids = eq == std::string::npos ? std::string() : spec.substr(eq + 1);
                    if (ids.empty()) dc.certificates.push_back(*rca.calculate_digest()); // clause 6.3.2: at least the RCA itself
                    for (std::size_t from = 0; from < ids.size();) {
                        const auto comma = ids.find(',', from);
                        const ByteBuffer raw = from_hex(ids.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
                        if (raw.size() != 8) throw std::runtime_error("--dc URL=HASHEDID8,... needs 8-octet hex digests");
                        HashedId8 id; std::copy(raw.begin(), raw.end(), id.begin());
                        dc.certificates.push_back(id);
                        from = comma == std::string::npos ? ids.size() : comma + 1;
                    }
                    entries.dc.push_back(std::move(dc));
                }
            }
            if (entries.dc.empty()) throw std::runtime_error("a root CTL needs at least one --dc URL (TS 102 941 clause 6.3.4)");
            message = vanetza_idf::pki::build_rca_ctl(backend, at, rca, key, entries, next_update, std::stoul(one(options, "--sequence", "1")));
            if (message) {
                const auto back = vanetza_idf::pki::parse_rca_ctl(backend, *message, rca);
                if (!back) throw std::runtime_error("the CTL does not read back (an entry not issued by this root?)");
            }
        } else {
            std::vector<HashedId8> revoked;
            if (auto it = options.find("--revoke"); it != options.end()) {
                for (const auto& spec : it->second) {
                    const ByteBuffer raw = from_hex(spec);
                    if (raw.size() != 8) throw std::runtime_error("--revoke needs an 8-octet hex HashedId8");
                    HashedId8 id; std::copy(raw.begin(), raw.end(), id.begin());
                    revoked.push_back(id);
                }
            }
            const auto this_update = static_cast<vanetza_idf::pki::Time32>(std::chrono::duration_cast<std::chrono::seconds>(at.time_since_epoch()).count());
            message = vanetza_idf::pki::build_crl(backend, at, rca, key, revoked, this_update, next_update);
        }
        if (!message) throw std::runtime_error("the root cannot sign this list (missing CTL/CRL appPermissions, psid 624/622?)");
        write_file(out, *message);
        std::printf("%s written: %zu octets -> %s\n", command == "ctl" ? "RCA CTL" : "CRL", message->size(), out.c_str());
        return 0;
    }
    if (command == "verify") {
        const auto& args = options.at("positional");
        std::vector<Certificate> loaded;
        for (const auto& path : args) loaded.push_back(load_certificate(path));
        std::vector<const Certificate*> chain;
        for (const auto& c : loaded) chain.push_back(&c);
        const bool ok = chain_ok(domain, chain);
        std::printf("%s\n", ok ? "chain verifies" : "chain does NOT verify");
        return ok ? 0 : 1;
    }
    if (command == "enrol-request") {
        const Certificate ea = load_certificate(one(options, "--ea"));
        const auto canonical = load_key(one(options, "--canonical-key"), backend);
        const std::string its_id_str = one(options, "--its-id");
        vanetza_idf::pki::EnrolmentRequestParameters params;
        params.its_id.assign(its_id_str.begin(), its_id_str.end());
        const auto ec_key = ecies.generate_key(KeyType::NistP256);
        params.verification_key = ec_key;
        params.app_permissions = parse_permissions(options, {{aid::SCR, {0x01, 0xc0}}});
        params.outer_signer_key = canonical.priv;
        const Clock::time_point at = options.count("--start") ? parse_time(one(options, "--start")) : now();
        ByteBuffer request;
        vanetza_idf::pki::RequestContext context;
        if (vanetza_idf::pki::build_enrolment_request(backend, ecies, at, params, ea, request, context) != vanetza_idf::Result::accepted)
            throw std::runtime_error("EnrolmentRequest not built (missing EA encryptionKey or bad parameters)");
        write_file(one(options, "--out"), request);
        write_context(one(options, "--context"), context);
        write_file(one(options, "--out-key"), ec_key.priv.key);
        std::printf("EnrolmentRequest written: %zu octets -> %s\n", request.size(), one(options, "--out").c_str());
        return 0;
    }
    if (command == "enrol-response") {
        const Certificate ea = load_certificate(one(options, "--ea"));
        const auto context = read_context(one(options, "--context"));
        const ByteBuffer response = read_file(one(options, "--response"));
        vanetza_idf::pki::EnrolmentResponse decoded;
        if (vanetza_idf::pki::parse_enrolment_response(backend, ecies, context, ea, response, decoded) != vanetza_idf::Result::accepted)
            throw std::runtime_error("EnrolmentResponse rejected (decrypt/signature/requestHash failure)");
        if (decoded.response_code != 0 || !decoded.certificate)
            throw std::runtime_error("EA declined the request, responseCode " + std::to_string(decoded.response_code));
        write_file(one(options, "--out"), decoded.certificate->encode());
        std::printf("EC written -> %s (HashedId8 %s)\n", one(options, "--out").c_str(), digest_hex(*decoded.certificate).c_str());
        return 0;
    }
    if (command == "authorize-request") {
        const Certificate ea = load_certificate(one(options, "--ea"));
        const Certificate aa = load_certificate(one(options, "--aa"));
        const Certificate ec = load_certificate(one(options, "--ec"));
        const auto ec_key = load_key(one(options, "--ec-key"), backend).priv;
        vanetza_idf::pki::AuthorizationRequestParameters params;
        const auto at_key = ecies.generate_key(KeyType::NistP256);
        params.verification_key = at_key;
        params.app_permissions = parse_permissions(options, {{aid::CA, {0x01, 0xff, 0xfc}}, {aid::VRU, {0x01}}});
        const unsigned hours = std::stoul(one(options, "--hours", "24"));
        const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : default_start(&ec);
        params.validity_period = std::make_pair(start, static_cast<std::uint16_t>(hours));
        params.ec = &ec;
        params.ec_key = ec_key;
        ByteBuffer request;
        vanetza_idf::pki::RequestContext context;
        if (vanetza_idf::pki::build_authorization_request(backend, ecies, now(), params, ea, aa, request, context) != vanetza_idf::Result::accepted)
            throw std::runtime_error("AuthorizationRequest not built");
        write_file(one(options, "--out"), request);
        write_context(one(options, "--context"), context);
        write_file(one(options, "--out-key"), at_key.priv.key);
        std::printf("AuthorizationRequest written: %zu octets -> %s\n", request.size(), one(options, "--out").c_str());
        return 0;
    }
    if (command == "authorize-response") {
        const Certificate aa = load_certificate(one(options, "--aa"));
        const auto context = read_context(one(options, "--context"));
        const ByteBuffer response = read_file(one(options, "--response"));
        vanetza_idf::pki::AuthorizationResponse decoded;
        if (vanetza_idf::pki::parse_authorization_response(backend, ecies, context, aa, response, decoded) != vanetza_idf::Result::accepted)
            throw std::runtime_error("AuthorizationResponse rejected (decrypt/signature/requestHash failure)");
        if (decoded.response_code != 0 || !decoded.certificate)
            throw std::runtime_error("AA declined the request, responseCode " + std::to_string(decoded.response_code));
        write_file(one(options, "--out"), decoded.certificate->encode());
        std::printf("AT written -> %s (HashedId8 %s)\n", one(options, "--out").c_str(), digest_hex(*decoded.certificate).c_str());
        return 0;
    }
    if (command == "ea-respond") {
        vidf_test::Credential ea;
        ea.certificate = load_certificate(one(options, "--ea"));
        ea.key = load_key(one(options, "--ea-key"), backend).priv;
        const auto ea_encryption_key = load_key(one(options, "--ea-enc-key"), backend).priv;
        const bool has_canonical = options.count("--canonical-key") != 0;
        const bool has_current_ec = options.count("--current-ec") != 0;
        if (has_canonical == has_current_ec)
            throw std::runtime_error("give exactly one of --canonical-key (initial enrolment) or --current-ec (re-enrolment)");
        std::optional<PublicKey> canonical_pub;
        std::optional<Certificate> current_ec;
        if (has_canonical) canonical_pub = load_key(one(options, "--canonical-key"), backend).pub;
        else current_ec = load_certificate(one(options, "--current-ec"));
        const ByteBuffer request = read_file(one(options, "--request"));
        std::array<std::uint8_t, 16> aes_key {};
        auto parsed = vidf_test::parse_enrolment_request(backend, ecies, ea, ea_encryption_key, request,
                                                          canonical_pub ? &*canonical_pub : nullptr,
                                                          current_ec ? &*current_ec : nullptr, aes_key);
        vidf_test::Authority authority {backend, ecies};
        ByteBuffer response;
        if (!parsed) {
            std::printf("ea-respond: request did not decrypt/verify/decode; nothing was issued\n");
            return 1;
        }
        if (options.count("--deny")) {
            response = authority.enrolment_response(now(), aes_key, request,
                                                     static_cast<std::uint8_t>(std::stoul(one(options, "--deny"))), nullptr, ea);
        } else {
            const std::string name = one(options, "--name", "vidf-station EC");
            const unsigned hours = std::stoul(one(options, "--hours", "8760"));
            const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : now() - std::chrono::hours(1);
            const auto ec = domain.issue_credential_for(ea, parsed->verification_key, name, start, hours);
            response = authority.enrolment_response(now(), aes_key, request, 0, &ec, ea);
            const std::string ec_id = options.count("--id") ? one(options, "--id") : digest_hex(ec);
            store(one(options, "--dir"), ec_id, ec, nullptr);
        }
        write_file(one(options, "--out"), response);
        std::printf("EnrolmentResponse written: %zu octets -> %s\n", response.size(), one(options, "--out").c_str());
        return 0;
    }
    if (command == "aa-respond") {
        vidf_test::Credential aa;
        aa.certificate = load_certificate(one(options, "--aa"));
        aa.key = load_key(one(options, "--aa-key"), backend).priv;
        const auto aa_encryption_key = load_key(one(options, "--aa-enc-key"), backend).priv;
        vidf_test::Credential ea;
        ea.certificate = load_certificate(one(options, "--ea"));
        ea.key = load_key(one(options, "--ea-key"), backend).priv;
        const auto ea_encryption_key = load_key(one(options, "--ea-enc-key"), backend).priv;
        const ByteBuffer request = read_file(one(options, "--request"));
        std::array<std::uint8_t, 16> aes_key {};
        auto parsed = vidf_test::parse_authorization_request(backend, ecies, aa, aa_encryption_key, request, aes_key);
        vidf_test::Authority authority {backend, ecies};
        if (!parsed) {
            std::printf("aa-respond: request did not decrypt/verify/decode; nothing was issued\n");
            return 1;
        }
        std::optional<Certificate> claimant;
        {
            const std::string ec_dir = one(options, "--ec-dir");
            std::ifstream index(ec_dir + "/index.lst");
            std::string hex_id, filename;
            while (index >> hex_id >> filename) {
                try {
                    Certificate candidate = load_certificate(ec_dir + "/" + filename);
                    if (vidf_test::validate_entitlement(backend, ecies, ea, ea_encryption_key, *parsed, candidate)) {
                        claimant = candidate;
                        break;
                    }
                } catch (const std::exception&) { continue; }
            }
        }
        ByteBuffer response;
        if (options.count("--deny") || !claimant) {
            const auto code = options.count("--deny") ? static_cast<std::uint8_t>(std::stoul(one(options, "--deny"))) : std::uint8_t(1);
            response = authority.authorization_response(now(), aes_key, request, code, nullptr, aa);
            if (!claimant) std::printf("aa-respond: no EC under --ec-dir signed this SharedAtRequest; entitlement not validated\n");
        } else {
            const unsigned hours = std::stoul(one(options, "--hours", "24"));
            const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : now() - std::chrono::hours(1);
            const auto at = domain.issue_ticket_for(aa, parsed->verification_key, parsed->app_permissions, start, hours);
            response = authority.authorization_response(now(), aes_key, request, 0, &at, aa);
        }
        write_file(one(options, "--out"), response);
        std::printf("AuthorizationResponse written: %zu octets -> %s\n", response.size(), one(options, "--out").c_str());
        return 0;
    }
    const std::string dir = one(options, "--out");
    const std::string id = one(options, "--id");
    if (command == "root") {
        const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : default_start(nullptr);
        const auto key = load_key(one(options, "--key"), backend);
        const unsigned years = std::stoul(one(options, "--years", "5"));
        const auto certificate = options.count("--like")
            ? domain.issue_root_like(key.priv, key.pub, one(options, "--name"), start, years, load_certificate(one(options, "--like")))
            : domain.issue_root(key.priv, key.pub, one(options, "--name"), start, years);
        store(dir, id, certificate, nullptr); // the root key stays where it is
        return 0;
    }
    if (command == "authority") {
        vidf_test::Credential issuer;
        issuer.certificate = load_certificate(one(options, "--issuer"));
        issuer.key = load_key(one(options, "--issuer-key"), backend).priv;
        if (issuer.certificate.issuer_is_self() && !domain.verify_chain_signature(issuer.certificate, issuer.certificate))
            throw std::runtime_error("issuer certificate does not verify with itself");
        const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : default_start(&issuer.certificate);
        PrivateKey encryption_key;
        const auto authority = domain.issue_authority(issuer, one(options, "--name"), start, std::stoul(one(options, "--years", "3")), &encryption_key);
        if (!authority.certificate.is_ca_certificate())
            throw std::runtime_error("the issuer has no certIssuePermissions group reaching two certificates down; nothing to delegate");
        if (!chain_ok(domain, {&authority.certificate, &issuer.certificate})) throw std::runtime_error("refusing to write an inconsistent authority certificate");
        store(dir, id, authority.certificate, &authority.key);
        write_file(dir + "/" + id + ".ekey", encryption_key.key);
        std::printf("%s ECIES encryption key -> %s/%s.ekey (clause 6.2.3: needed to answer real requests)\n", id.c_str(), dir.c_str(), id.c_str());
        return 0;
    }
    if (command == "ticket") {
        vidf_test::Credential issuer;
        issuer.certificate = load_certificate(one(options, "--issuer"));
        issuer.key = load_key(one(options, "--issuer-key"), backend).priv;
        const auto permissions = parse_permissions(options,
            {{aid::CA, {0x01, 0xff, 0xfc}}, {aid::DEN, {0x01, 0xff, 0xff, 0xff}}, {aid::VRU, {0x01}}, {aid::GN_MGMT, {}}});
        const unsigned hours = std::stoul(one(options, "--hours", "24"));
        const Clock::time_point start = options.count("--start") ? parse_time(one(options, "--start")) : default_start(&issuer.certificate);
        vidf_test::Credential ticket;
        if (options.count("--region")) {
            long lat, lon, radius;
            if (std::sscanf(one(options, "--region").c_str(), "%ld,%ld,%ld", &lat, &lon, &radius) != 3)
                throw std::runtime_error("--region LAT,LON,RADIUS_M in 1/10 microdegrees and metres");
            ticket = domain.issue_ticket(issuer, permissions, start, hours,
                                         vidf_test::TrustDomain::CircularRegion {static_cast<std::int32_t>(lat), static_cast<std::int32_t>(lon), static_cast<std::uint16_t>(radius)});
        } else {
            ticket = domain.issue_ticket(issuer, permissions, start, hours, issuer.certificate->toBeSigned.region); // inherits the issuer's region
        }
        std::vector<Certificate> more;
        std::vector<const Certificate*> chain {&ticket.certificate, &issuer.certificate};
        if (options.count("--root")) { more.push_back(load_certificate(one(options, "--root"))); chain.push_back(&more.back()); }
        if (!chain_ok(domain, chain)) throw std::runtime_error("refusing to write a ticket the issuer cannot authorise (permissions, region or validity)");
        store(dir, id, ticket.certificate, &ticket.key);
        return 0;
    }
    std::fprintf(stderr, "unknown command %s\n", command.c_str());
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "vidf_issue: %s\n", e.what());
    return 1;
}
