// TS 102 941 V2.2.1 enrolment and authorization round trips against the test
// trust domain: the EA/AA side is simulated here with the same primitives
// (decrypt as recipient, verify the signatures, issue, respond), the station
// side is the library. Nothing is accepted on decoding alone.
#include "check.hpp"
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
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/asn1/security/PublicVerificationKey.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <chrono>
#include <cstring>

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
using Mgmt = vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data>;

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

// ---- EA side helpers (test only) --------------------------------------------------
struct Authority {
    Backend& backend;
    pki::EciesBackend& ecies;
    const vidf_test::TrustDomain& domain;

    // TS 102 941 clause 6.2.3.2.2: EtsiTs102941Data{enrolmentResponse} signed by the EA, encrypted with the request key
    ByteBuffer enrolment_response(const std::array<std::uint8_t, 16>& aes_key, const ByteBuffer& request,
                                  std::uint8_t code, const v3::Certificate* ec, const vidf_test::Credential& signer) {
        Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        mgmt->version = Vanetza_Security_Version_v1;
        mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse;
        auto& inner = mgmt->content.choice.enrolmentResponse;
        const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
        OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
        inner.responseCode = code;
        if (ec) {
            auto* certificate = v3::asn1::allocate<Vanetza_Security_EtsiTs103097Certificate_t>();
            inner.certificate = reinterpret_cast<struct Vanetza_Security_EtsiTs103097Certificate*>(certificate);
            v3::Certificate copy(*ec);
            const auto bytes = copy.encode();
            void* target = certificate;
            check(vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &target, bytes), "EC copied into response");
        }
        auto signed_bytes = pki::sign_data(backend, t0, HashAlgorithm::SHA256, mgmt.encode(), signer.key, &signer.certificate);
        check(signed_bytes.has_value(), "EA signs the response");
        auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
        check(encrypted.has_value(), "EA encrypts the response with the request key");
        return *encrypted;
    }

    ByteBuffer authorization_response(const std::array<std::uint8_t, 16>& aes_key, const ByteBuffer& request,
                                      std::uint8_t code, const v3::Certificate* at) {
        Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        mgmt->version = Vanetza_Security_Version_v1;
        mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse;
        auto& inner = mgmt->content.choice.authorizationResponse;
        const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
        OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
        inner.responseCode = code;
        if (at) {
            auto* certificate = v3::asn1::allocate<Vanetza_Security_EtsiTs103097Certificate_t>();
            inner.certificate = reinterpret_cast<struct Vanetza_Security_EtsiTs103097Certificate*>(certificate);
            v3::Certificate copy(*at);
            const auto bytes = copy.encode();
            void* target = certificate;
            check(vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &target, bytes), "AT copied into response");
        }
        auto signed_bytes = pki::sign_data(backend, t0, HashAlgorithm::SHA256, mgmt.encode(), domain.aa.key, &domain.aa.certificate);
        check(signed_bytes.has_value(), "AA signs the response");
        auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
        check(encrypted.has_value(), "AA encrypts the response with the request key");
        return *encrypted;
    }
};

PublicKey public_key_of(const Vanetza_Security_PublicVerificationKey& key) {
    v3::Certificate probe; // reuse the certificate accessor by planting the key into a scratch certificate
    probe->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    const auto bytes = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &key);
    void* target = &probe->toBeSigned.verifyKeyIndicator.choice.verificationKey;
    check(vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &target, bytes), "verification key copied");
    auto out = v3::get_public_key(*probe.content());
    check(out.has_value(), "verification key readable");
    return *out;
}

bool same_point(const PublicKey& a, const PublicKey& b) {
    return a.type == b.type && a.x == b.x;
}

void test_enrolment_and_authorization(Backend& backend, pki::EciesBackend& ecies) {
    vidf_test::section("test_enrolment_and_authorization");
    vidf_test::TrustDomain domain(backend, t0);
    Authority authority {backend, ecies, domain};
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
    // EA: decrypt with its private encryption key
    std::array<std::uint8_t, 16> ea_seen_key {};
    auto outer = pki::decrypt_as_recipient(backend, ecies, domain.ea.certificate, domain.ea_encryption_key, request, &ea_seen_key);
    check(outer.has_value() && ea_seen_key == ec_context.aes_key, "EA decrypts the request and recovers the AES key");
    check(!pki::decrypt_as_recipient(backend, ecies, domain.aa.certificate, domain.aa_encryption_key, request),
          "AA cannot decrypt a request addressed to the EA");
    // outer signature: self-signed with the canonical key, psid 623
    auto mgmt_bytes = pki::verify_signed(backend, *outer, &canonical.pub, nullptr, aid::SCR);
    check(mgmt_bytes.has_value(), "outer EtsiTs103097Data-Signed verifies with the canonical key");
    check(!pki::verify_signed(backend, *outer, &ec_params.verification_key.pub, nullptr, aid::SCR), "outer signature is not by the new key");
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    check(mgmt.decode(*mgmt_bytes) && mgmt->version == 1 &&
          mgmt->content.present == Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest, "EtsiTs102941Data v1 enrolmentRequest");
    // proof of possession: self-signed with the new verification key
    const auto pop_bytes = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &mgmt->content.choice.enrolmentRequest);
    auto inner_bytes = pki::verify_signed(backend, pop_bytes, &ec_params.verification_key.pub, nullptr, aid::SCR);
    check(inner_bytes.has_value(), "InnerEcRequestSignedForPop verifies with the new verification key");
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    check(inner.decode(*inner_bytes) && inner->certificateFormat == 1 &&
          ByteBuffer(inner->itsId.buf, inner->itsId.buf + inner->itsId.size) == ec_params.its_id,
          "InnerEcRequest carries itsId and certificateFormat ts103097v131");
    check(same_point(public_key_of(inner->publicKeys.verificationKey), ec_params.verification_key.pub),
          "InnerEcRequest carries the requested verification key");
    check(inner->requestedSubjectAttributes.appPermissions && inner->requestedSubjectAttributes.appPermissions->list.count == 1 &&
          !inner->requestedSubjectAttributes.certIssuePermissions, "requested attributes: appPermissions only");
    // EA issues the EC and answers
    const auto ec = domain.issue_credential_for(ec_params.verification_key.pub, "vidf-station EC", t0 - std::chrono::hours(1), 24 * 365);
    const ByteBuffer response = authority.enrolment_response(ec_context.aes_key, request, 0, &ec, domain.ea);
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
    const ByteBuffer forged = authority.enrolment_response(ec_context.aes_key, request, 0, &ec, domain.aa);
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, forged, ec_response) == Result::rejected,
          "response signed by a different authority rejected");
    const ByteBuffer denied = authority.enrolment_response(ec_context.aes_key, request, 3, nullptr, domain.ea);
    check(pki::parse_enrolment_response(backend, ecies, ec_context, domain.ea.certificate, denied, ec_response) == Result::accepted &&
          ec_response.response_code == 3 && !ec_response.certificate, "negative response without certificate is reported");
    const ByteBuffer dishonest = authority.enrolment_response(ec_context.aes_key, request, 0, nullptr, domain.ea);
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
    outer = pki::decrypt_as_recipient(backend, ecies, domain.ea.certificate, domain.ea_encryption_key, renew_request);
    check(outer && pki::verify_signed(backend, *outer, nullptr, &ec, aid::SCR), "re-enrolment outer signature by the EC digest");
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
    // AA: decrypt, verify POP, check keyTag, forward the EC signature to the EA
    auto pop = pki::decrypt_as_recipient(backend, ecies, domain.aa.certificate, domain.aa_encryption_key, at_request);
    check(pop.has_value(), "AA decrypts the request");
    auto at_mgmt_bytes = pki::verify_signed(backend, *pop, &at_params.verification_key.pub, nullptr, aid::SCR);
    check(at_mgmt_bytes.has_value(), "proof of possession verifies with the new AT key");
    Mgmt at_mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    check(at_mgmt.decode(*at_mgmt_bytes) && at_mgmt->content.present == Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest,
          "EtsiTs102941Data authorizationRequest");
    auto& iar = at_mgmt->content.choice.authorizationRequest;
    check(same_point(public_key_of(iar.publicKeys.verificationKey), at_params.verification_key.pub) && !iar.publicKeys.encryptionKey,
          "InnerAtRequest carries the AT verification key only");
    const ByteBuffer hmac_key(iar.hmacKey.buf, iar.hmacKey.buf + iar.hmacKey.size);
    const auto tag = ecies.hmac_sha256(hmac_key, vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &iar.publicKeys.verificationKey));
    check(hmac_key.size() == 32 && iar.sharedAtRequest.keyTag.size == 16 && std::memcmp(tag.data(), iar.sharedAtRequest.keyTag.buf, 16) == 0,
          "keyTag = leftmost 16 octets of HMAC-SHA256(hmacKey, OER(publicKeys))");
    const auto ea_id = *domain.ea.certificate.calculate_digest();
    check(iar.sharedAtRequest.eaId.size == 8 && std::memcmp(iar.sharedAtRequest.eaId.buf, ea_id.data(), 8) == 0 &&
          iar.sharedAtRequest.certificateFormat == 1, "SharedAtRequest names the EA");
    check(iar.sharedAtRequest.requestedSubjectAttributes.validityPeriod && iar.sharedAtRequest.requestedSubjectAttributes.appPermissions &&
          iar.sharedAtRequest.requestedSubjectAttributes.appPermissions->list.count == 2, "requested validity and permissions present");
    check(iar.ecSignature.present == Vanetza_Security_EcSignature_PR_encryptedEcSignature, "EC signature encrypted for the EA (privacy)");
    // EA (authorization validation): decrypt the EC signature and check it against the SharedAtRequest
    const auto enc_sig = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &iar.ecSignature.choice.encryptedEcSignature);
    auto ec_signed = pki::decrypt_as_recipient(backend, ecies, domain.ea.certificate, domain.ea_encryption_key, enc_sig);
    check(ec_signed.has_value(), "EA decrypts the EC signature");
    auto external = pki::verify_signed(backend, *ec_signed, nullptr, &ec, aid::SCR);
    check(external.has_value() && external->empty(), "external-payload signature by the EC verifies");
    v3::SecuredMessage ext;
    check(ext.decode(*ec_signed), "SignedExternalPayload decodes");
    const auto* hashed = ext->content->choice.signedData->tbsData->payload->extDataHash;
    const auto shared_encoded = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &iar.sharedAtRequest);
    const auto shared_hash = calculate_sha256_digest(shared_encoded.data(), shared_encoded.size());
    check(hashed && hashed->present == Vanetza_Security_HashedData_PR_sha256HashedData && hashed->choice.sha256HashedData.size == 32 &&
          std::memcmp(hashed->choice.sha256HashedData.buf, shared_hash.data(), 32) == 0, "extDataHash = SHA-256 of SharedAtRequest");
    // AA issues the AT and answers
    const auto at = domain.issue_ticket_for(at_params.verification_key.pub, at_params.app_permissions, t0 - std::chrono::hours(1), 24);
    const ByteBuffer at_response = authority.authorization_response(at_context.aes_key, at_request, 0, &at);
    pki::AuthorizationResponse parsed;
    check(pki::parse_authorization_response(backend, ecies, at_context, domain.aa.certificate, at_response, parsed) == Result::accepted &&
          parsed.response_code == 0 && parsed.certificate, "AuthorizationResponse accepted");
    check(pki::parse_authorization_response(backend, ecies, at_context, domain.ea.certificate, at_response, parsed) == Result::rejected,
          "AT response signed by the AA is rejected when the EA is expected");
    // the new AT with the station's own key enters the pool and signs
    vanetza_idf::security::CertificatePool pool(backend);
    check(pool.add(parsed.certificate->encode(), at_params.verification_key.priv) == Result::accepted,
          "AT from the response and the generated key form a usable ticket");
    check(pool.add(parsed.certificate->encode(), canonical.priv) == Result::invalid_argument, "another key does not match the AT");
    // ---- No privacy / no POP variant ----
    at_params.privacy = false;
    at_params.include_pop = false;
    ByteBuffer plain_request;
    pki::RequestContext plain_context;
    check(pki::build_authorization_request(backend, ecies, t0, at_params, domain.ea.certificate, domain.aa.certificate, plain_request, plain_context) == Result::accepted,
          "AuthorizationRequest without POP built");
    auto envelope = pki::decrypt_as_recipient(backend, ecies, domain.aa.certificate, domain.aa_encryption_key, plain_request);
    v3::SecuredMessage unsecured;
    check(envelope && unsecured.decode(*envelope) && !unsecured.is_signed() && !unsecured.is_encrypted(), "unsecured envelope without POP");
    auto payload = unsecured.payload();
    const auto& packet = boost::get<CohesivePacket>(payload);
    auto view = create_byte_view(packet, OsiLayer::Network, max_osi_layer());
    Mgmt plain_mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    check(plain_mgmt.decode(ByteBuffer(view.begin(), view.end())) &&
          plain_mgmt->content.choice.authorizationRequest.ecSignature.present == Vanetza_Security_EcSignature_PR_ecSignature,
          "EC signature in clear without privacy");
    at_params.hash = HashAlgorithm::SHA384;
    check(pki::build_authorization_request(backend, ecies, t0, at_params, domain.ea.certificate, domain.aa.certificate, plain_request, plain_context) == Result::unsupported,
          "SHA-384 external hash is refused, not silently downgraded");
}
} // namespace

void test_pki() {
    vidf_test::TestBackend backend;
    TestEcies ecies;
    test_ecies(backend, ecies);
    test_enrolment_and_authorization(backend, ecies);
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
