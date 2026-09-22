// TS 102 941 V2.2.1 enrolment and authorization round trips against the test
// trust domain: the EA/AA side uses the shared authority-side tooling of
// pki_authority.hpp (the same tooling vidf_issue's ea-respond/aa-respond commands
// use against real, separately-run requests), the station side is the library.
// Nothing is accepted on decoding alone.
#include "check.hpp"
#include "pki_authority.hpp"
#include "test_backend.hpp"
#include "test_trust_domain.hpp"
#include <vanetza_idf/pki.hpp>
#include <vanetza_idf/security.hpp>
#if VIDF_BACKEND_OPENSSL
#include <vanetza_idf/ecies_openssl.hpp>
#endif
#if VIDF_BACKEND_MBEDTLS
#include <vanetza_idf/ecies_mbedtls.hpp>
#endif
#include <algorithm>
#include <chrono>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza_idf;
using vidf_test::check;

namespace {
#if VIDF_BACKEND_OPENSSL
using TestEcies = pki::EciesOpenSsl;
#else
using TestEcies = pki::EciesMbedTls;
#endif
const Clock::time_point t0 = Clock::time_point(std::chrono::seconds(716292005));

void test_ecies(Backend& backend, pki::EciesBackend& ecies) {
    vidf_test::section("test_ecies");
    for (auto type : {KeyType::NistP256, KeyType::BrainpoolP256r1}) {
        const auto recipient = ecies.generate_key(type);
        const ByteBuffer p1 = backend.calculate_hash(HashAlgorithm::SHA256, {1, 2, 3});
        std::array<std::uint8_t, 16> aes {};
        const auto rnd = ecies.random(16);
        std::copy(rnd.begin(), rnd.end(), aes.begin());
        auto wrapped = pki::ecies_encrypt_key(backend, ecies, recipient.pub, p1, aes);
        check(wrapped.has_value() && wrapped->v.type == type, "ECIES wraps the AES key with an ephemeral point");
        auto opened = pki::ecies_decrypt_key(backend, ecies, recipient.priv, p1, *wrapped);
        check(opened && *opened == aes, "recipient recovers the AES key");
        // compressed ephemeral point on the wire is accepted as well
        pki::EncryptedKey compressed = *wrapped;
        compressed.v.compression = (wrapped->v.y.back() & 1) ? KeyCompression::Y1 : KeyCompression::Y0;
        compressed.v.y.clear();
        opened = pki::ecies_decrypt_key(backend, ecies, recipient.priv, p1, compressed);
        check(opened && *opened == aes, "compressed ephemeral point decompressed for ECDH");
        auto tampered = *wrapped; tampered.t[0] ^= 1;
        check(!pki::ecies_decrypt_key(backend, ecies, recipient.priv, p1, tampered), "bad authentication tag refused");
        auto other = ecies.generate_key(type);
        check(!pki::ecies_decrypt_key(backend, ecies, other.priv, p1, *wrapped), "another private key refused");
        check(!pki::ecies_decrypt_key(backend, ecies, recipient.priv, ByteBuffer {9}, *wrapped), "other P1 refused");
    }
    // KDF2: 32-octet blocks, counter from 1, output truncated to the requested length
    const ByteBuffer z = {0x01, 0x02};
    const auto k48 = pki::kdf2_sha256(backend, z, {}, 48);
    const auto k32 = pki::kdf2_sha256(backend, z, {}, 32);
    check(k48.size() == 48 && std::equal(k32.begin(), k32.end(), k48.begin()), "KDF2 prefix property");
    ByteBuffer block1 = z; block1.insert(block1.end(), {0, 0, 0, 1});
    check(backend.calculate_hash(HashAlgorithm::SHA256, block1) == k32, "KDF2 first block = H(Z || 00000001 || P1)");
    // AES-CCM symmetric round trip with PSK recipient info
    std::array<std::uint8_t, 16> psk {};
    const auto rnd = ecies.random(16);
    std::copy(rnd.begin(), rnd.end(), psk.begin());
    const ByteBuffer secret_text = {0x10, 0x20, 0x30, 0x40, 0x50};
    auto enc = pki::encrypt_with_psk(ecies, psk, secret_text);
    check(enc.has_value(), "psk encryption");
    auto dec = pki::decrypt_with_psk(ecies, psk, *enc);
    check(dec && *dec == secret_text, "psk decryption round trip");
    std::array<std::uint8_t, 16> wrong = psk; wrong[3] ^= 0x40;
    check(!pki::decrypt_with_psk(ecies, wrong, *enc), "pskRecipInfo mismatch refused before decryption");
    ByteBuffer corrupt = *enc; corrupt[corrupt.size() - 3] ^= 0x01;
    check(!pki::decrypt_with_psk(ecies, psk, corrupt), "CCM tag failure refused");
}

bool same_point(const PublicKey& a, const PublicKey& b) {
    return a.type == b.type && a.x == b.x;
}

void test_enrolment_and_authorization(Backend& backend, pki::EciesBackend& ecies) {
    vidf_test::section("test_enrolment_and_authorization");
    vidf_test::TrustDomain domain(backend, t0);
    vidf_test::Authority authority {backend, ecies};
    // ---- Enrolment (clause 6.2.3.2): initial request with the canonical key ----
    const pki::KeyPair canonical = ecies.generate_key(KeyType::NistP256);
    pki::EnrolmentRequestParameters ec_params;
    ec_params.its_id = ByteBuffer {'v', 'i', 'd', 'f', '-', 's', 't', 'a', 't', 'i', 'o', 'n'};
    ec_params.verification_key = ecies.generate_key(KeyType::NistP256);
    ec_params.app_permissions = {{aid::SCR, {0x01, 0xc0}}};
    ec_params.outer_signer_key = canonical.priv;
    ByteBuffer request;
    pki::RequestContext ec_context;
    check(pki::build_enrolment_request(backend, ecies, t0, ec_params, domain.ea.certificate, request, ec_context) == Result::accepted,
          "EnrolmentRequest built");
    check(pki::build_enrolment_request(backend, ecies, t0, ec_params, domain.root.certificate, request, ec_context) == Result::invalid_argument,
          "recipient without encryption key refused");
    // EA: decrypt, verify the outer signature and the proof of possession, decode
    std::array<std::uint8_t, 16> ea_seen_key {};
    auto parsed = vidf_test::parse_enrolment_request(backend, ecies, domain.ea, domain.ea_encryption_key, request,
                                                      &canonical.pub, nullptr, ea_seen_key);
    check(parsed.has_value() && ea_seen_key == ec_context.aes_key, "EA decrypts the request and recovers the AES key");
    check(parsed && same_point(parsed->verification_key, ec_params.verification_key.pub),
          "InnerEcRequest carries the requested verification key");
    check(parsed && parsed->its_id == ec_params.its_id, "InnerEcRequest carries itsId");
    check(parsed && !parsed->re_enrolment, "initial enrolment, not a re-enrolment");
    check(parsed && parsed->app_permissions.size() == 1, "requested attributes: appPermissions only");
    {
        std::array<std::uint8_t, 16> discard {};
        check(!vidf_test::parse_authorization_request(backend, ecies, domain.aa, domain.aa_encryption_key, request, discard).has_value(),
              "AA cannot decrypt a request addressed to the EA");
        check(!vidf_test::parse_enrolment_request(backend, ecies, domain.ea, domain.ea_encryption_key, request,
                                                   &ec_params.verification_key.pub, nullptr, discard).has_value(),
              "outer signature is not by the new key");
    }
    // EA issues the EC and answers
    const auto ec = domain.issue_credential_for(parsed->verification_key, "vidf-station EC", t0 - std::chrono::hours(1), 24 * 365);
    const ByteBuffer response = authority.enrolment_response(t0, ec_context.aes_key, request, 0, &ec, domain.ea);
    pki::EnrolmentResponse ec_response;
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, response, ec_response) == Result::accepted,
          "EnrolmentResponse accepted");
    check(ec_response.response_code == 0 && ec_response.certificate && ec_response.certificate->encode() == ec.encode(),
          "EC returned unchanged");
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.aa.certificate, response, ec_response) == Result::rejected,
          "response signed by the EA is rejected when the AA is expected");
    pki::RequestContext other_context = ec_context; other_context.request_hash[0] ^= 1;
    check(pki::parse_enrolment_response(backend, ecies, other_context, domain.ea.certificate, response, ec_response) == Result::rejected,
          "requestHash mismatch rejected");
    other_context = ec_context; other_context.aes_key[5] ^= 1;
    check(pki::parse_enrolment_response(backend, ecies, other_context, domain.ea.certificate, response, ec_response) == Result::rejected,
          "response encrypted for another request rejected");
    const ByteBuffer forged = authority.enrolment_response(t0, ec_context.aes_key, request, 0, &ec, domain.aa);
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, forged, ec_response) == Result::rejected,
          "response signed by a different authority rejected");
    const ByteBuffer denied = authority.enrolment_response(t0, ec_context.aes_key, request, 3, nullptr, domain.ea);
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, denied, ec_response) == Result::accepted &&
          ec_response.response_code == 3 && !ec_response.certificate, "negative response without certificate is reported");
    const ByteBuffer dishonest = authority.enrolment_response(t0, ec_context.aes_key, request, 0, nullptr, domain.ea);
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, dishonest, ec_response) == Result::rejected,
          "positive response without certificate rejected");
    // ---- Re-enrolment: outer signer = digest of the current EC ----
    pki::EnrolmentRequestParameters renew = ec_params;
    const auto ec_id = *ec.calculate_digest();
    renew.its_id.assign(ec_id.begin(), ec_id.end());
    renew.verification_key = ecies.generate_key(KeyType::NistP256);
    renew.outer_signer_key = ec_params.verification_key.priv;
    renew.current_ec = &ec;
    pki::RequestContext renew_context;
    ByteBuffer renew_request;
    check(pki::build_enrolment_request(backend, ecies, t0, renew, domain.ea.certificate, renew_request, renew_context) == Result::accepted,
          "re-enrolment request built");
    std::array<std::uint8_t, 16> renew_seen_key {};
    auto reparsed = vidf_test::parse_enrolment_request(backend, ecies, domain.ea, domain.ea_encryption_key, renew_request,
                                                        nullptr, &ec, renew_seen_key);
    check(reparsed.has_value() && reparsed->re_enrolment && reparsed->its_id == renew.its_id,
          "re-enrolment outer signature by the EC digest");
    // ---- Authorization (clause 6.2.3.3) with privacy and POP ----
    pki::AuthorizationRequestParameters at_params;
    at_params.verification_key = ecies.generate_key(KeyType::NistP256);
    at_params.app_permissions = {{aid::VRU, {0x01}}, {aid::CA, {0x01, 0xff, 0xfc}}};
    at_params.validity_period = std::make_pair(t0 - std::chrono::hours(1), std::uint16_t(24));
    at_params.ec = &ec;
    at_params.ec_key = ec_params.verification_key.priv;
    ByteBuffer at_request;
    pki::RequestContext at_context;
    check(pki::build_authorization_request(backend, ecies, t0, at_params, domain.ea.certificate, domain.aa.certificate, at_request, at_context) == Result::accepted,
          "AuthorizationRequest built");
    // AA: decrypt, verify the proof of possession, decode
    std::array<std::uint8_t, 16> aa_seen_key {};
    auto at_parsed = vidf_test::parse_authorization_request(backend, ecies, domain.aa, domain.aa_encryption_key, at_request, aa_seen_key);
    check(at_parsed.has_value(), "AA decrypts, verifies and decodes the request");
    check(at_parsed && same_point(at_parsed->verification_key, at_params.verification_key.pub),
          "InnerAtRequest carries the AT verification key");
    check(at_parsed && at_parsed->app_permissions.size() == 2, "requested permissions present");
    const auto ea_id = *domain.ea.certificate.calculate_digest();
    check(at_parsed && std::equal(ea_id.begin(), ea_id.end(), at_parsed->ea_id.begin()), "SharedAtRequest names the EA");
    check(at_parsed && at_parsed->ec_signature_encrypted, "EC signature encrypted for the EA (privacy)");
    // EA (authorization validation, the diagram's "AA <-> EA"): decrypt the EC signature
    // and check it against the SharedAtRequest -- the entitlement check itself
    check(at_parsed && vidf_test::validate_entitlement(backend, ecies, domain.ea, domain.ea_encryption_key, *at_parsed, ec),
          "EA validates the EC's entitlement");
    const auto impostor = domain.issue_credential_for(ecies.generate_key(KeyType::NistP256).pub, "impostor",
                                                       t0 - std::chrono::hours(1), 24);
    check(at_parsed && !vidf_test::validate_entitlement(backend, ecies, domain.ea, domain.ea_encryption_key, *at_parsed, impostor),
          "entitlement check rejects a certificate that did not sign this request");
    // AA issues the AT and answers
    const auto at = domain.issue_ticket_for(at_parsed->verification_key, at_parsed->app_permissions, t0 - std::chrono::hours(1), 24);
    const ByteBuffer at_response = authority.authorization_response(t0, at_context.aes_key, at_request, 0, &at, domain.aa);
    pki::AuthorizationResponse at_response_parsed;
    check(pki::parse_authorization_response(backend, ecies, at_context, domain.aa.certificate, at_response, at_response_parsed) == Result::accepted &&
          at_response_parsed.response_code == 0 && at_response_parsed.certificate, "AuthorizationResponse accepted");
    check(pki::parse_authorization_response(backend, ecies, at_context, domain.ea.certificate, at_response, at_response_parsed) == Result::rejected,
          "AT response signed by the AA is rejected when the EA is expected");
    // the new AT with the station's own key enters the pool and signs
    vanetza_idf::security::CertificatePool pool(backend);
    check(pool.add(at_response_parsed.certificate->encode(), at_params.verification_key.priv) == Result::accepted,
          "AT from the response and the generated key form a usable ticket");
    check(pool.add(at_response_parsed.certificate->encode(), canonical.priv) == Result::invalid_argument, "another key does not match the AT");
    // ---- No privacy / no POP variant ----
    at_params.privacy = false;
    at_params.include_pop = false;
    ByteBuffer plain_request;
    pki::RequestContext plain_context;
    check(pki::build_authorization_request(backend, ecies, t0, at_params, domain.ea.certificate, domain.aa.certificate, plain_request, plain_context) == Result::accepted,
          "AuthorizationRequest without POP built");
    std::array<std::uint8_t, 16> plain_seen_key {};
    auto plain_parsed = vidf_test::parse_authorization_request(backend, ecies, domain.aa, domain.aa_encryption_key, plain_request, plain_seen_key);
    check(plain_parsed.has_value() && !plain_parsed->ec_signature_encrypted, "EC signature in clear without privacy, decoded without POP");
    at_params.hash = HashAlgorithm::SHA384;
    check(pki::build_authorization_request(backend, ecies, t0, at_params, domain.ea.certificate, domain.aa.certificate, plain_request, plain_context) == Result::unsupported,
          "SHA-384 external hash is refused, not silently downgraded");
}
} // namespace

// TS 102 941 V2.2.1 clause 6.3: the RCA's CTL and CRL as built for a distribution centre
// and as an ITS-S reads them (clause 6.3.6: signed by its RCA, otherwise nothing is taken).
void test_trust_lists(Backend& backend) {
    vidf_test::section("test_trust_lists");
    const Clock::time_point now = Clock::time_point(std::chrono::seconds(716292005));
    vidf_test::TrustDomain domain {backend, now};
    vidf_test::TrustDomain other {backend, now};
    const auto root_id = *domain.root.certificate.calculate_digest();
    const auto aa_id = *domain.aa.certificate.calculate_digest();
    pki::TrustListEntries entries;
    entries.ea.push_back({domain.ea.certificate.encode(), "http://ea.example.test/"});
    entries.aa.push_back({domain.aa.certificate.encode(), "http://aa.example.test/"});
    entries.dc.push_back({"http://dc.example.test/", {root_id}});
    const pki::Time32 next_update = 716292005 + 7 * 86400;
    auto ctl = pki::build_rca_ctl(backend, now, domain.root.certificate, domain.root.key, entries, next_update, 3);
    check(ctl.has_value() && !ctl->empty(), "RCA CTL built (FullCtl, sequence 3)");
    // 1. It reads back, signed by the RCA, with every entry.
    auto list = pki::parse_rca_ctl(backend, *ctl, domain.root.certificate);
    check(list.has_value(), "CTL verifies against the RCA that signed it");
    if (list) {
        check(list->sequence == 3 && list->next_update == next_update && list->full, "CTL sequence, nextUpdate and isFullCtl");
        check(list->ea.size() == 1 && list->aa.size() == 1 && *list->aa[0].calculate_digest() == aa_id, "EA and AA entries decoded");
        check(list->dc.size() == 1 && list->dc[0].url == "http://dc.example.test/" && list->dc[0].certificates == std::vector<HashedId8> {root_id},
              "DC entry with the RCA digest");
    }
    // 2. Not by another root, not tampered, not with a foreign AA.
    check(!pki::parse_rca_ctl(backend, *ctl, other.root.certificate), "a CTL of another RCA is refused");
    { ByteBuffer bad = *ctl; bad[bad.size() / 2] ^= 0x01; check(!pki::parse_rca_ctl(backend, bad, domain.root.certificate), "a tampered CTL is refused"); }
    {
        pki::TrustListEntries foreign;
        foreign.aa.push_back({other.aa.certificate.encode(), ""});
        auto bad = pki::build_rca_ctl(backend, now, domain.root.certificate, domain.root.key, foreign, next_update, 4);
        check(bad && !pki::parse_rca_ctl(backend, *bad, domain.root.certificate), "an AA not issued by the RCA is refused even inside its signed CTL");
    }
    {   // an RCA without the CTL permission cannot sign one (TS 103 097 clause 7.2.3)
        auto ticket = domain.issue_ticket({{aid::VRU, {0x01}}}, now - std::chrono::hours(1), 24);
        check(!pki::build_rca_ctl(backend, now, ticket.certificate, ticket.key, entries, next_update, 1), "a certificate without psid 624 signs no CTL");
    }
    // 3. Applied: the authorities become issuers.
    {
        vanetza_idf::security::TrustConfiguration trust;
        check(trust.add_root(domain.root.certificate.encode()) == Result::accepted, "root provisioned");
        check(pki::apply(*list, trust) == 2 && trust.authorities().size() == 3, "CTL adds EA and AA as issuers");
        check(pki::apply(*list, trust) == 0, "applying the same CTL again adds nothing");
    }
    // 4. CRL: revoking the AA.
    auto crl = pki::build_crl(backend, now, domain.root.certificate, domain.root.key, {aa_id}, 716292005, next_update);
    check(crl.has_value(), "CRL built");
    auto revoked = pki::parse_crl(backend, *crl, domain.root.certificate);
    check(revoked && revoked->revoked == std::vector<HashedId8> {aa_id} && revoked->this_update == 716292005 && revoked->next_update == next_update,
          "CRL verifies and lists the AA");
    check(!pki::parse_crl(backend, *crl, other.root.certificate), "a CRL of another RCA is refused");
    check(!pki::parse_rca_ctl(backend, *crl, domain.root.certificate) && !pki::parse_crl(backend, *ctl, domain.root.certificate),
          "a CRL is no CTL and a CTL no CRL (psid)");
    {
        vanetza_idf::security::TrustConfiguration trust;
        trust.add_root(domain.root.certificate.encode());
        check(pki::apply(*revoked, domain.root.certificate, trust) == 1 && trust.revocations().is_revoked(root_id, aa_id) &&
              !trust.revocations().is_revoked(root_id, root_id), "CRL entries become revocations by the RCA");
        auto empty = pki::build_crl(backend, now, domain.root.certificate, domain.root.key, {}, 716292005, next_update);
        auto none = pki::parse_crl(backend, *empty, domain.root.certificate);
        check(none && pki::apply(*none, domain.root.certificate, trust) == 0 && !trust.revocations().is_revoked(root_id, aa_id),
              "a newer empty CRL replaces the earlier list");
    }
}

void test_pki() {
    vidf_test::TestBackend backend;
    TestEcies ecies;
    test_ecies(backend, ecies);
    test_enrolment_and_authorization(backend, ecies);
    test_trust_lists(backend);
#if VIDF_BACKEND_OPENSSL && VIDF_BACKEND_MBEDTLS
    // Cross-check: the PSA primitives interoperate with the OpenSSL ones.
    pki::EciesMbedTls psa;
    const auto recipient = psa.generate_key(KeyType::NistP256);
    const ByteBuffer p1 = backend.calculate_hash(HashAlgorithm::SHA256, {7});
    std::array<std::uint8_t, 16> aes {};
    auto wrapped = pki::ecies_encrypt_key(backend, ecies, recipient.pub, p1, aes);
    auto opened = pki::ecies_decrypt_key(backend, psa, recipient.priv, p1, *wrapped);
    check(opened && *opened == aes, "OpenSSL-wrapped key opened by PSA ECDH/HMAC");
    wrapped = pki::ecies_encrypt_key(backend, psa, recipient.pub, p1, aes);
    opened = pki::ecies_decrypt_key(backend, ecies, recipient.priv, p1, *wrapped);
    check(opened && *opened == aes, "PSA-wrapped key opened by OpenSSL");
    std::array<std::uint8_t, 12> nonce {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    ByteBuffer ct, pt;
    check(psa.aes_ccm_encrypt(aes, nonce, {1, 2, 3}, ct) && ecies.aes_ccm_decrypt(aes, nonce, ct, pt) && pt == ByteBuffer {1, 2, 3},
          "PSA AES-CCM ciphertext accepted by OpenSSL");
    check(ecies.aes_ccm_encrypt(aes, nonce, {4, 5}, ct) && psa.aes_ccm_decrypt(aes, nonce, ct, pt) && pt == ByteBuffer {4, 5},
          "OpenSSL AES-CCM ciphertext accepted by PSA");
    check(psa.hmac_sha256({1}, {2}) == ecies.hmac_sha256({1}, {2}), "HMAC-SHA256 agrees across backends");
    test_enrolment_and_authorization(backend, psa);
#endif
}
