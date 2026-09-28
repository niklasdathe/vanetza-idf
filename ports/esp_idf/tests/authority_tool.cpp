// Minimal ETSI TS 102 941 EA/AA request processor for the Docker laboratory PKI.
// It deliberately reuses the same request/response and certificate primitives as
// the port regression tests. HTTP policy, authentication and persistence live in
// implementation/dc-service; this executable only transforms one OER request.
#include "test_backend.hpp"
#include "test_trust_domain.hpp"
#include <vanetza_idf/ecies_openssl.hpp>
#include <vanetza_idf/pki.hpp>
#include <vanetza_idf/security.hpp>
#include <vanetza_idf/its_time.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/asn1/security/PublicVerificationKey.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/common/byte_view.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza_idf;
namespace fs = std::filesystem;

namespace {
using Mgmt = vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data>;
using Options = std::map<std::string, std::vector<std::string>>;

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

Options parse(int argc, char** argv, int from) {
    Options options;
    for (int i = from; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--", 0) == 0 && i + 1 < argc) options[arg].push_back(argv[++i]);
        else options["positional"].push_back(arg);
    }
    return options;
}

std::string one(const Options& options, const char* name, const char* fallback = nullptr) {
    auto it = options.find(name);
    if (it != options.end() && !it->second.empty()) return it->second.back();
    if (fallback) return fallback;
    throw std::runtime_error(std::string("missing ") + name);
}

Clock::time_point now() {
    return Clock::time_point(vanetza_idf::its_time::since_epoch(std::chrono::system_clock::now()));
}

v3::Certificate load_certificate(const std::string& path) {
    v3::Certificate certificate;
    if (!certificate.decode(read_file(path))) throw std::runtime_error("not a COER certificate: " + path);
    return certificate;
}

PrivateKey load_raw_key(const std::string& path) {
    PrivateKey key;
    key.type = KeyType::NistP256;
    key.key = read_file(path);
    if (key.key.size() != 32) throw std::runtime_error("raw key is not a 32-octet NIST P-256 scalar: " + path);
    return key;
}

PublicKey public_from_evp(EVP_PKEY* pkey) {
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != NID_X9_62_prime256v1) {
        if (ec) EC_KEY_free(ec);
        throw std::runtime_error("canonical key is not NIST P-256");
    }
    const EC_POINT* point = EC_KEY_get0_public_key(ec);
    BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
    if (!point || !x || !y || EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec), point, x, y, nullptr) != 1) {
        BN_free(x); BN_free(y); EC_KEY_free(ec);
        throw std::runtime_error("cannot read canonical public key");
    }
    PublicKey out; out.type = KeyType::NistP256; out.compression = KeyCompression::NoCompression;
    out.x.assign(32, 0); out.y.assign(32, 0);
    BN_bn2binpad(x, out.x.data(), 32); BN_bn2binpad(y, out.y.data(), 32);
    BN_free(x); BN_free(y); EC_KEY_free(ec);
    return out;
}

PublicKey load_pem_public_key(const std::string& path) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("cannot open " + path);
    EVP_PKEY* key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    if (!key) { std::rewind(fp); key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr); }
    std::fclose(fp);
    if (!key) throw std::runtime_error("cannot read canonical PEM key");
    PublicKey out = public_from_evp(key); EVP_PKEY_free(key); return out;
}

PublicKey public_key_of(const Vanetza_Security_PublicVerificationKey& key) {
    v3::Certificate probe;
    probe->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    const auto bytes = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &key);
    void* target = &probe->toBeSigned.verifyKeyIndicator.choice.verificationKey;
    if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &target, bytes))
        throw std::runtime_error("cannot decode requested verification key");
    auto out = v3::get_public_key(*probe.content());
    if (!out) throw std::runtime_error("requested verification key is unavailable");
    return *out;
}

ByteBuffer message_payload(const ByteBuffer& encoded) {
    v3::SecuredMessage message;
    if (!message.decode(encoded)) throw std::runtime_error("cannot decode secured message");
    const auto payload = message.payload();
    const auto* packet = boost::get<CohesivePacket>(&payload);
    if (!packet) throw std::runtime_error("secured message has no inline payload");
    const auto view = create_byte_view(*packet, OsiLayer::Network, max_osi_layer());
    return ByteBuffer(view.begin(), view.end());
}

vidf_test::Credential authority(const std::string& cert, const std::string& key,
                                const std::string& encryption_key) {
    vidf_test::Credential out;
    out.certificate = load_certificate(cert);
    out.key = load_raw_key(key);
    out.encryption_key = load_raw_key(encryption_key);
    return out;
}

struct Vanetza_Security_EtsiTs103097Certificate* copy_certificate(const v3::Certificate& certificate) {
    auto* value = v3::asn1::allocate<Vanetza_Security_EtsiTs103097Certificate_t>();
    const ByteBuffer encoded = certificate.encode();
    void* target = value;
    if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &target, encoded))
        throw std::runtime_error("cannot attach issued certificate to response");
    return reinterpret_cast<struct Vanetza_Security_EtsiTs103097Certificate*>(value);
}

ByteBuffer enrolment_response(Backend& backend, pki::EciesBackend& ecies,
                              const vidf_test::Credential& ea,
                              const std::array<std::uint8_t, 16>& aes_key,
                              const ByteBuffer& request, const v3::Certificate& ec) {
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse;
    auto& inner = mgmt->content.choice.enrolmentResponse;
    const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
    OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
    inner.responseCode = 0;
    inner.certificate = copy_certificate(ec);
    auto signed_bytes = pki::sign_data(backend, now(), HashAlgorithm::SHA256, mgmt.encode(), ea.key, &ea.certificate);
    if (!signed_bytes) throw std::runtime_error("EA could not sign response");
    auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
    if (!encrypted) throw std::runtime_error("EA could not encrypt response");
    return *encrypted;
}

ByteBuffer authorization_response(Backend& backend, pki::EciesBackend& ecies,
                                  const vidf_test::Credential& aa,
                                  const std::array<std::uint8_t, 16>& aes_key,
                                  const ByteBuffer& request, const v3::Certificate& at) {
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse;
    auto& inner = mgmt->content.choice.authorizationResponse;
    const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
    OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
    inner.responseCode = 0;
    inner.certificate = copy_certificate(at);
    auto signed_bytes = pki::sign_data(backend, now(), HashAlgorithm::SHA256, mgmt.encode(), aa.key, &aa.certificate);
    if (!signed_bytes) throw std::runtime_error("AA could not sign response");
    auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
    if (!encrypted) throw std::runtime_error("AA could not encrypt response");
    return *encrypted;
}

pki::Permissions requested_permissions(const Vanetza_Security_SequenceOfPsidSsp* values) {
    pki::Permissions out;
    if (!values) return out;
    for (int i = 0; i < values->list.count; ++i) {
        const auto* entry = values->list.array[i];
        if (!entry) continue;
        ByteBuffer ssp;
        if (entry->ssp && entry->ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp)
            ssp.assign(entry->ssp->choice.bitmapSsp.buf, entry->ssp->choice.bitmapSsp.buf + entry->ssp->choice.bitmapSsp.size);
        else if (entry->ssp && entry->ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_opaque)
            ssp.assign(entry->ssp->choice.opaque.buf, entry->ssp->choice.opaque.buf + entry->ssp->choice.opaque.size);
        out.emplace_back(static_cast<ItsAid>(entry->psid), std::move(ssp));
    }
    return out;
}

std::optional<v3::Certificate> verify_ec_signature(Backend& backend, pki::EciesBackend& ecies,
                                                    const vidf_test::Credential& ea,
                                                    const Vanetza_Security_InnerAtRequest& request,
                                                    const fs::path& ec_dir) {
    ByteBuffer signed_ec;
    if (request.ecSignature.present == Vanetza_Security_EcSignature_PR_encryptedEcSignature) {
        const auto encoded = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data,
                                                       &request.ecSignature.choice.encryptedEcSignature);
        auto decrypted = pki::decrypt_as_recipient(backend, ecies, ea.certificate, ea.encryption_key, encoded);
        if (!decrypted) return std::nullopt;
        signed_ec = std::move(*decrypted);
    } else if (request.ecSignature.present == Vanetza_Security_EcSignature_PR_ecSignature) {
        signed_ec = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data,
                                              &request.ecSignature.choice.ecSignature);
    } else return std::nullopt;

    const auto shared = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &request.sharedAtRequest);
    const auto expected = calculate_sha256_digest(shared.data(), shared.size());
    v3::SecuredMessage message;
    if (!message.decode(signed_ec) || !message->content ||
        message->content->present != Vanetza_Security_Ieee1609Dot2Content_PR_signedData) return std::nullopt;
    const auto* hashed = message->content->choice.signedData->tbsData->payload->extDataHash;
    if (!hashed || hashed->present != Vanetza_Security_HashedData_PR_sha256HashedData ||
        hashed->choice.sha256HashedData.size != 32 ||
        std::memcmp(hashed->choice.sha256HashedData.buf, expected.data(), 32) != 0) return std::nullopt;

    for (const auto& item : fs::directory_iterator(ec_dir)) {
        if (!item.is_regular_file() || item.path().extension() != ".oer") continue;
        try {
            auto ec = load_certificate(item.path().string());
            auto verified = pki::verify_signed(backend, signed_ec, nullptr, &ec, aid::SCR);
            if (verified && verified->empty()) return ec;
        } catch (...) {}
    }
    return std::nullopt;
}
} // namespace

int main(int argc, char** argv) try {
    if (argc < 2) throw std::runtime_error("usage: vidf_authority enrol|authorize [options]");
    const std::string command = argv[1];
    const Options options = parse(argc, argv, 2);
    vidf_test::TestBackend backend;
    pki::EciesOpenSsl ecies;
    vidf_test::TrustDomain domain(backend, now());
    const ByteBuffer request = read_file(one(options, "--request"));
    std::array<std::uint8_t, 16> aes_key {};

    if (command == "enrol") {
        const auto ea = authority(one(options, "--ea-cert"), one(options, "--ea-key"), one(options, "--ea-encryption-key"));
        auto outer = pki::decrypt_as_recipient(backend, ecies, ea.certificate, ea.encryption_key, request, &aes_key);
        if (!outer) throw std::runtime_error("EA cannot decrypt enrolment request");
        const ByteBuffer unverified = message_payload(*outer);
        Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        if (!mgmt.decode(unverified) || mgmt->version != 1 ||
            mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest)
            throw std::runtime_error("not an enrolment request");
        const auto pop = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data,
                                                   &mgmt->content.choice.enrolmentRequest);
        const ByteBuffer inner_unverified = message_payload(pop);
        vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
        if (!inner.decode(inner_unverified)) throw std::runtime_error("cannot decode InnerEcRequest");
        const PublicKey station_key = public_key_of(inner->publicKeys.verificationKey);
        if (!pki::verify_signed(backend, pop, &station_key, nullptr, aid::SCR))
            throw std::runtime_error("enrolment proof of possession failed");
        if (options.count("--canonical-key")) {
            const PublicKey canonical = load_pem_public_key(one(options, "--canonical-key"));
            if (!pki::verify_signed(backend, *outer, &canonical, nullptr, aid::SCR))
                throw std::runtime_error("canonical enrolment signature failed");
        } else if (!options.count("--allow-indirect")) {
            throw std::runtime_error("canonical key is not registered; use --canonical-key or explicit --allow-indirect policy");
        }
        const std::string name(reinterpret_cast<const char*>(inner->itsId.buf), inner->itsId.size);
        const auto ec = domain.issue_credential_for(ea, station_key, name, now() - std::chrono::minutes(1), 24 * 365);
        write_file(one(options, "--certificate-out"), ec.encode());
        write_file(one(options, "--response-out"), enrolment_response(backend, ecies, ea, aes_key, request, ec));
        return 0;
    }

    if (command == "authorize") {
        const auto aa = authority(one(options, "--aa-cert"), one(options, "--aa-key"), one(options, "--aa-encryption-key"));
        const auto ea = authority(one(options, "--ea-cert"), one(options, "--ea-key"), one(options, "--ea-encryption-key"));
        auto envelope = pki::decrypt_as_recipient(backend, ecies, aa.certificate, aa.encryption_key, request, &aes_key);
        if (!envelope) throw std::runtime_error("AA cannot decrypt authorization request");
        // The authorization envelope is a signed POP message. Decode its payload only
        // far enough to obtain the requested public key, then authenticate that same
        // payload before any request fields are trusted.
        const ByteBuffer unverified = message_payload(*envelope);
        Mgmt probe(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        if (!probe.decode(unverified) ||
            probe->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest)
            throw std::runtime_error("not an authorization request");
        const PublicKey pop_key = public_key_of(
            probe->content.choice.authorizationRequest.publicKeys.verificationKey);
        auto verified = pki::verify_signed(backend, *envelope, &pop_key, nullptr, aid::SCR);
        if (!verified) throw std::runtime_error("authorization proof of possession failed");
        ByteBuffer mgmt_bytes = std::move(*verified);
        Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        if (!mgmt.decode(mgmt_bytes) || mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest)
            throw std::runtime_error("cannot decode authorization request");
        auto& inner = mgmt->content.choice.authorizationRequest;
        const PublicKey station_key = public_key_of(inner.publicKeys.verificationKey);
        if (!verify_ec_signature(backend, ecies, ea, inner, one(options, "--ec-dir")))
            throw std::runtime_error("no enrolled EC validates this authorization request");
        const auto permissions = requested_permissions(inner.sharedAtRequest.requestedSubjectAttributes.appPermissions);
        if (permissions.empty()) throw std::runtime_error("authorization request has no appPermissions");
        const auto at = domain.issue_ticket_for(aa, station_key, permissions, now() - std::chrono::minutes(1), 24 * 7);
        write_file(one(options, "--certificate-out"), at.encode());
        write_file(one(options, "--response-out"), authorization_response(backend, ecies, aa, aes_key, request, at));
        return 0;
    }
    throw std::runtime_error("unknown command " + command);
} catch (const std::exception& error) {
    std::fprintf(stderr, "vidf_authority: %s\n", error.what());
    return 1;
}
