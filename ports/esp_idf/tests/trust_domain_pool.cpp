// Writes an ISOLATED TEST trust domain in the file layout the ETSI ITS test
// framework's certificate loader reads (ccsrc/Protocols/Security/
// certificates_loader.cc): <name>.oer (COER certificate), <name>.vkey (raw
// private signing key), <name>.ekey (raw private encryption key, authorities
// only) and index.lst ("<HashedId8 hex> <name>.oer" per line).
//
//   vidf_test_pool <directory> [<validity hours for the tickets, default 24>]
//
// Names follow the ATS defaults (LibItsSecurity_TypesAndValues.ttcn /
// LibItsSecurity_Pixits.ttcn): the IUT chain CERT_IUT_A_RCA -> CERT_IUT_A_AA
// -> CERT_IUT_A_AT and the test-system chain CERT_TS_A_AA -> CERT_TS_A_AT
// under the same root. Tickets carry CA, DEN, GN-MGMT and VRU permissions
// and start one minute before generation (TC_SEC_ITSS_SND_GENMSG_05_BV expects
// the start within five minutes of the current time). This is not a PKI.
#include "test_backend.hpp"
#include "test_trust_domain.hpp"
#include <vanetza_idf/its_time.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

namespace {
using namespace vanetza;
using vanetza::security::v3::Certificate;

// ITS time (TAI since 2004-01-01T00:00:00Z) from the library's tested conversion.
Clock::time_point its_now() {
    return Clock::time_point(vanetza_idf::its_time::since_epoch(std::chrono::system_clock::now()));
}

bool write(const std::string& path, const ByteBuffer& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return static_cast<bool>(out);
}

std::string hex(const vanetza::security::HashedId8& id) {
    static const char* digits = "0123456789ABCDEF";
    std::string s;
    for (auto b : id) { s += digits[b >> 4]; s += digits[b & 15]; }
    return s;
}
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: vidf_test_pool <directory> [ticket hours]\n"); return 2; }
    const std::string dir = argv[1];
    const unsigned hours = argc > 2 ? static_cast<unsigned>(std::atoi(argv[2])) : 24;
    const auto now = its_now();
    vidf_test::TestBackend backend;
    vidf_test::TrustDomain domain(backend, now);
    const vidf_test::TrustDomain::Permissions permissions {
        {aid::CA, {0x01, 0xff, 0xfc}}, {aid::DEN, {0x01, 0xff, 0xff, 0xff}}, {aid::GN_MGMT, {}}, {aid::VRU, {0x01}}};
    const auto start = now - std::chrono::minutes(1);
    const auto iut_at = domain.issue_ticket(permissions, start, hours);
    const auto ts_aa = domain.issue_authority("vanetza-idf test-system AA", now - std::chrono::hours(1));
    const auto ts_at = domain.issue_ticket(ts_aa, permissions, start, hours);
    struct Entry { const char* name; const Certificate* certificate; const vanetza::security::PrivateKey* key; };
    const std::vector<Entry> entries {
        {"CERT_IUT_A_RCA", &domain.root.certificate, &domain.root.key},
        {"CERT_IUT_A_AA", &domain.aa.certificate, &domain.aa.key},
        {"CERT_IUT_A_AT", &iut_at.certificate, &iut_at.key},
        {"CERT_TS_A_AA", &ts_aa.certificate, &ts_aa.key},
        {"CERT_TS_A_AT", &ts_at.certificate, &ts_at.key},
    };
    std::string index;
    for (const auto& entry : entries) {
        const auto digest = entry.certificate->calculate_digest();
        if (!digest || !write(dir + "/" + entry.name + ".oer", entry.certificate->encode()) ||
            !write(dir + "/" + entry.name + ".vkey", entry.key->key)) {
            std::fprintf(stderr, "cannot write %s\n", entry.name);
            return 1;
        }
        index += hex(*digest) + " " + entry.name + ".oer\n";
    }
    std::ofstream(dir + "/index.lst") << index;
    std::printf("%s", index.c_str());
    return 0;
}
