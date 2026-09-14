// Credentials bundle (credentials.hpp): the octets a provisioning path hands over and a
// storage keeps; applied to the trust configuration and the ticket pool through the
// same checks a station's own provisioning goes through. NVS storage on the device.
#include "check.hpp"
#include "test_backend.hpp"
#include "test_trust_domain.hpp"
#include <vanetza_idf/credentials.hpp>
#if VIDF_NVS_CREDENTIALS
#include <vanetza_idf/nvs_credential_store.hpp>
#endif
#include <chrono>
#include <cstdio>

using namespace vanetza;
using namespace vanetza_idf;
using namespace std::chrono_literals;
using vidf_test::check;
namespace sec = vanetza_idf::security;

namespace {
const Clock::time_point t0 = Clock::time_point(std::chrono::seconds(716292005));
const vidf_test::TrustDomain::Permissions vam_permissions {{aid::VRU, {0x01}}, {aid::GN_MGMT, {}}};

bool same(const sec::Credentials& a, const sec::Credentials& b) {
    if (a.roots != b.roots || a.authorities != b.authorities || a.tickets.size() != b.tickets.size()) return false;
    for (std::size_t i = 0; i < a.tickets.size(); ++i) {
        if (a.tickets[i].certificate != b.tickets[i].certificate || a.tickets[i].key.type != b.tickets[i].key.type ||
            a.tickets[i].key.key != b.tickets[i].key.key) return false;
    }
    return true;
}
} // namespace

void test_credentials() {
    vidf_test::section("test_credentials");
    vidf_test::TestBackend backend;
    vidf_test::TrustDomain domain {backend, t0};
    auto ticket = domain.issue_ticket(vam_permissions, t0 - 1h, 24);
    auto spare = domain.issue_ticket(vam_permissions, t0 - 1h, 24);
    sec::Credentials credentials;
    credentials.roots.push_back(domain.root.certificate.encode());
    credentials.authorities.push_back(domain.aa.certificate.encode());
    credentials.tickets.push_back({ticket.certificate.encode(), ticket.key});
    credentials.tickets.push_back({spare.certificate.encode(), spare.key});

    // 1. The bundle round-trips and is what it says (magic, records).
    const ByteBuffer bundle = sec::encode(credentials);
    check(bundle.size() > 4 && bundle[0] == 'V' && bundle[1] == 'C' && bundle[2] == 'R' && bundle[3] == '1', "bundle carries the VCR1 magic");
    sec::Credentials decoded;
    check(sec::decode(bundle, decoded) && same(decoded, credentials), "encode/decode round trip keeps roots, authorities, tickets and keys");
    check(sec::decode(sec::encode(sec::Credentials {}), decoded) && decoded.empty(), "an empty bundle decodes to nothing");

    // 2. Malformed bundles fail closed and leave the output untouched.
    sec::Credentials untouched = credentials;
    auto rejects = [&](ByteBuffer bad, const char* what) {
        sec::Credentials out = credentials;
        check(!sec::decode(bad, out) && same(out, untouched), what);
    };
    { ByteBuffer bad = bundle; bad[3] = '2'; rejects(bad, "wrong magic rejected"); }
    { ByteBuffer bad(bundle.begin(), bundle.end() - 5); rejects(bad, "truncated record rejected"); }
    { ByteBuffer bad = bundle; bad.push_back(9); bad.push_back(0); bad.push_back(1); bad.push_back(0); rejects(bad, "unknown record type rejected"); }
    { ByteBuffer bad = bundle; bad.push_back(1); bad.push_back(0); bad.push_back(0); rejects(bad, "empty record rejected"); }
    {   // a key record without its ticket, and a ticket without a key
        sec::Credentials one; one.tickets.push_back(credentials.tickets[0]);
        ByteBuffer bad = sec::encode(one);
        const std::size_t key_at = 4 + 3 + one.tickets[0].certificate.size();
        ByteBuffer key_only(bad.begin(), bad.begin() + 4);
        key_only.insert(key_only.end(), bad.begin() + key_at, bad.end());
        rejects(key_only, "key record without a ticket rejected");
        ByteBuffer ticket_only(bad.begin(), bad.begin() + key_at);
        rejects(ticket_only, "ticket without its key rejected");
        bad[key_at + 3] = 7; // curve code
        rejects(bad, "unknown curve code rejected");
        bad[key_at + 3] = 3; // brainpoolP384r1 needs 48 octets, 32 given
        rejects(bad, "key length not matching the curve rejected");
    }

    // 3. apply(): everything through the trust configuration and the pool, in order.
    {
        sec::TrustConfiguration trust;
        sec::CertificatePool pool {backend};
        const auto report = sec::apply(credentials, trust, pool);
        check(report.result == Result::accepted && report.roots == 1 && report.authorities == 1 && report.tickets == 2 &&
              pool.size() == 2 && trust.authorities().size() == 2, "apply() feeds roots, authorities and tickets");
    }
    {   // the first refused item stops the application and is reported
        sec::Credentials broken = credentials;
        broken.tickets[1].key = ticket.key; // the spare ticket with the wrong key
        sec::TrustConfiguration trust;
        sec::CertificatePool pool {backend};
        const auto report = sec::apply(broken, trust, pool);
        check(report.result == Result::invalid_argument && report.roots == 1 && report.authorities == 1 && report.tickets == 1 && pool.size() == 1,
              "a ticket whose key does not match stops apply() with the count so far");
    }
    {
        sec::Credentials no_anchor = credentials;
        no_anchor.roots[0] = credentials.authorities[0]; // an AA is no root
        sec::TrustConfiguration trust;
        sec::CertificatePool pool {backend};
        check(sec::apply(no_anchor, trust, pool).result == Result::invalid_argument, "a non-root as root is refused");
    }

#ifndef ESP_PLATFORM
    // 4. File storage (hosts): save, load, erase.
    {
        sec::FileCredentialStore store {"vidf_test_credentials.bin"};
        check(store.save(credentials) == Result::accepted, "file store saves the bundle");
        sec::Credentials loaded;
        check(store.load(loaded) == Result::accepted && same(loaded, credentials), "file store loads it back");
        check(store.erase() == Result::accepted && store.load(loaded) == Result::rejected, "erased store loads nothing");
    }
#endif
#if VIDF_NVS_CREDENTIALS
    // 4. NVS storage (device): save, load, erase; NVS was initialised by the application.
    {
        sec::NvsCredentialStore store {"vidf_test", "creds"};
        store.erase();
        sec::Credentials loaded;
        check(store.load(loaded) == Result::rejected, "empty NVS store loads nothing");
        check(store.save(credentials) == Result::accepted, "NVS store saves the bundle");
        check(store.load(loaded) == Result::accepted && same(loaded, credentials), "NVS store loads it back");
        check(store.erase() == Result::accepted && store.load(loaded) == Result::rejected, "erased NVS store loads nothing");
    }
#endif
}
