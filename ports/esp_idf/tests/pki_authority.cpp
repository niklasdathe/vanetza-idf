#include "pki_authority.hpp"
#include <vanetza_idf/ecc.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/asn1/security/PublicVerificationKey.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <cstring>
#include <stdexcept>

namespace vidf_test {
using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza_idf;
using vanetza::security::v3::Certificate;
using Mgmt = vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data>;

namespace {

// Reads a PublicVerificationKey out of a scratch certificate accessor (there is no
// stand-alone converter): plant the key, then read it back through v3::get_public_key.
// A wire verification key is always compressed (TS 103 097 clause 6 canonical form:
// copy_curve_point() then leaves .y empty, only recording the parity); decompress it
// here so the result is safe to feed into code that expects an ordinary x/y key (e.g.
// building a new certificate around it) -- an empty .y silently reads as an all-zero
// coordinate downstream, embedding the wrong point about half the time.
std::optional<PublicKey> public_key_of(const Vanetza_Security_PublicVerificationKey& key) {
    Certificate probe;
    probe->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    const auto bytes = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &key);
    void* target = &probe->toBeSigned.verifyKeyIndicator.choice.verificationKey;
    if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &target, bytes)) return std::nullopt;
    const auto compact = v3::get_public_key(*probe.content());
    if (!compact) return std::nullopt;
    if (compact->compression == KeyCompression::NoCompression) return *compact;
    const auto point = vanetza_idf::ecc::decompress(compact->type, compact->x, compact->compression == KeyCompression::Y1);
    if (!point) return std::nullopt;
    PublicKey out = *compact;
    out.compression = KeyCompression::NoCompression;
    out.y = point->y;
    return out;
}

// The payload of a self-signed EtsiTs103097Data-Signed, read WITHOUT verifying the
// signature -- used only to bootstrap the candidate key a self-signed proof of possession
// carries in-band. Nothing extracted this way is trusted until the real verify_signed()
// call below succeeds against that same candidate key: a forged payload cannot both name
// an arbitrary key and carry a signature that verifies with it.
std::optional<ByteBuffer> peek_self_signed_payload(const ByteBuffer& encoded, ItsAid expected_psid) {
    v3::SecuredMessage data;
    if (!data.decode(encoded) || !data.is_signed() || data.protocol_version() != 3) return std::nullopt;
    if (data.its_aid() != expected_psid) return std::nullopt;
    const auto* signed_data = data->content->choice.signedData;
    if (signed_data->signer.present != Vanetza_Security_SignerIdentifier_PR_self) return std::nullopt;
    auto payload = data.payload();
    const auto* packet = boost::get<CohesivePacket>(&payload);
    if (!packet) return std::nullopt;
    const auto view = create_byte_view(*packet, OsiLayer::Network, max_osi_layer());
    return ByteBuffer(view.begin(), view.end());
}

} // namespace

ByteBuffer Authority::enrolment_response(Clock::time_point now, const std::array<std::uint8_t, 16>& aes_key,
                                         const ByteBuffer& request, std::uint8_t response_code,
                                         const Certificate* ec, const Credential& signer) const {
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse;
    auto& inner = mgmt->content.choice.enrolmentResponse;
    const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
    OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
    inner.responseCode = response_code;
    if (ec) {
        auto* certificate = v3::asn1::allocate<Vanetza_Security_EtsiTs103097Certificate_t>();
        inner.certificate = reinterpret_cast<struct Vanetza_Security_EtsiTs103097Certificate*>(certificate);
        Certificate copy(*ec);
        const auto bytes = copy.encode();
        void* target = certificate;
        if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &target, bytes))
            throw std::runtime_error("EC could not be copied into the enrolment response");
    }
    auto signed_bytes = pki::sign_data(backend, now, HashAlgorithm::SHA256, mgmt.encode(), signer.key, &signer.certificate);
    if (!signed_bytes) throw std::runtime_error("EA cannot sign the enrolment response (missing SCR appPermissions?)");
    auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
    if (!encrypted) throw std::runtime_error("EA cannot encrypt the enrolment response");
    return *encrypted;
}

ByteBuffer Authority::authorization_response(Clock::time_point now, const std::array<std::uint8_t, 16>& aes_key,
                                             const ByteBuffer& request, std::uint8_t response_code,
                                             const Certificate* at, const Credential& signer) const {
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse;
    auto& inner = mgmt->content.choice.authorizationResponse;
    const auto hash = backend.calculate_hash(HashAlgorithm::SHA256, request);
    OCTET_STRING_fromBuf(&inner.requestHash, reinterpret_cast<const char*>(hash.data()), 16);
    inner.responseCode = response_code;
    if (at) {
        auto* certificate = v3::asn1::allocate<Vanetza_Security_EtsiTs103097Certificate_t>();
        inner.certificate = reinterpret_cast<struct Vanetza_Security_EtsiTs103097Certificate*>(certificate);
        Certificate copy(*at);
        const auto bytes = copy.encode();
        void* target = certificate;
        if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &target, bytes))
            throw std::runtime_error("AT could not be copied into the authorization response");
    }
    auto signed_bytes = pki::sign_data(backend, now, HashAlgorithm::SHA256, mgmt.encode(), signer.key, &signer.certificate);
    if (!signed_bytes) throw std::runtime_error("AA cannot sign the authorization response (missing SCR appPermissions?)");
    auto encrypted = pki::encrypt_with_psk(ecies, aes_key, *signed_bytes);
    if (!encrypted) throw std::runtime_error("AA cannot encrypt the authorization response");
    return *encrypted;
}

std::optional<ParsedEnrolmentRequest> parse_enrolment_request(Backend& backend, pki::EciesBackend& ecies, const Credential& ea,
                                                               const PrivateKey& ea_encryption_key, const ByteBuffer& encoded,
                                                               const PublicKey* canonical_key, const Certificate* current_ec,
                                                               std::array<std::uint8_t, 16>& aes_key_out) {
    if ((canonical_key == nullptr) == (current_ec == nullptr)) return std::nullopt; // exactly one of the two
    auto outer = pki::decrypt_as_recipient(backend, ecies, ea.certificate, ea_encryption_key, encoded, &aes_key_out);
    if (!outer) return std::nullopt;
    auto mgmt_bytes = pki::verify_signed(backend, *outer, canonical_key, current_ec, aid::SCR);
    if (!mgmt_bytes) return std::nullopt;
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(*mgmt_bytes) || mgmt->version != Vanetza_Security_Version_v1 ||
        mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest) return std::nullopt;
    const auto pop_bytes = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &mgmt->content.choice.enrolmentRequest);
    // bootstrap: the PoP layer is self-signed with the very key it is requesting certified
    const auto peeked = peek_self_signed_payload(pop_bytes, aid::SCR);
    if (!peeked) return std::nullopt;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest> peek_inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    if (!peek_inner.decode(*peeked)) return std::nullopt;
    const auto candidate_key = public_key_of(peek_inner->publicKeys.verificationKey);
    if (!candidate_key) return std::nullopt;
    // authoritative check: the signature must actually verify with the candidate key
    auto inner_bytes = pki::verify_signed(backend, pop_bytes, &*candidate_key, nullptr, aid::SCR);
    if (!inner_bytes) return std::nullopt;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    if (!inner.decode(*inner_bytes) || inner->certificateFormat != Vanetza_Security_CertificateFormat_ts103097v131)
        return std::nullopt;
    ParsedEnrolmentRequest result;
    result.its_id.assign(inner->itsId.buf, inner->itsId.buf + inner->itsId.size);
    result.verification_key = *candidate_key;
    result.re_enrolment = (current_ec != nullptr);
    if (const auto* permissions = inner->requestedSubjectAttributes.appPermissions) {
        for (int i = 0; i < permissions->list.count; ++i) {
            const auto* entry = permissions->list.array[i];
            if (!entry) continue;
            ByteBuffer ssp;
            if (entry->ssp && entry->ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp)
                ssp.assign(entry->ssp->choice.bitmapSsp.buf, entry->ssp->choice.bitmapSsp.buf + entry->ssp->choice.bitmapSsp.size);
            result.app_permissions.emplace_back(static_cast<ItsAid>(entry->psid), std::move(ssp));
        }
    }
    return result;
}

std::optional<ParsedAuthorizationRequest> parse_authorization_request(Backend& backend, pki::EciesBackend& ecies, const Credential& aa,
                                                                       const PrivateKey& aa_encryption_key, const ByteBuffer& encoded,
                                                                       std::array<std::uint8_t, 16>& aes_key_out) {
    auto pop = pki::decrypt_as_recipient(backend, ecies, aa.certificate, aa_encryption_key, encoded, &aes_key_out);
    if (!pop) return std::nullopt;
    ByteBuffer mgmt_bytes;
    // bootstrap: with PoP, self-signed with the very AT key being requested (as for enrolment)
    if (const auto peeked = peek_self_signed_payload(*pop, aid::SCR)) {
        Mgmt peek_mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        if (!peek_mgmt.decode(*peeked) || peek_mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest)
            return std::nullopt;
        const auto candidate_key = public_key_of(peek_mgmt->content.choice.authorizationRequest.publicKeys.verificationKey);
        if (!candidate_key) return std::nullopt;
        auto verified = pki::verify_signed(backend, *pop, &*candidate_key, nullptr, aid::SCR);
        if (!verified) return std::nullopt;
        mgmt_bytes = *verified;
    } else {
        // clause 6.2.3.3.1 without proof of possession: an unsecured envelope
        v3::SecuredMessage unsecured;
        if (!unsecured.decode(*pop) || unsecured.is_signed() || unsecured.is_encrypted()) return std::nullopt;
        auto payload = unsecured.payload();
        const auto* packet = boost::get<CohesivePacket>(&payload);
        if (!packet) return std::nullopt;
        const auto view = create_byte_view(*packet, OsiLayer::Network, max_osi_layer());
        mgmt_bytes.assign(view.begin(), view.end());
    }
    Mgmt mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(mgmt_bytes) || mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest)
        return std::nullopt;
    auto& iar = mgmt->content.choice.authorizationRequest;
    const auto key = public_key_of(iar.publicKeys.verificationKey);
    if (!key) return std::nullopt;
    ParsedAuthorizationRequest result;
    result.verification_key = *key;
    if (iar.sharedAtRequest.eaId.size != 8) return std::nullopt;
    std::copy(iar.sharedAtRequest.eaId.buf, iar.sharedAtRequest.eaId.buf + 8, result.ea_id.begin());
    if (const auto* permissions = iar.sharedAtRequest.requestedSubjectAttributes.appPermissions) {
        for (int i = 0; i < permissions->list.count; ++i) {
            const auto* entry = permissions->list.array[i];
            if (!entry) continue;
            ByteBuffer ssp;
            if (entry->ssp && entry->ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp)
                ssp.assign(entry->ssp->choice.bitmapSsp.buf, entry->ssp->choice.bitmapSsp.buf + entry->ssp->choice.bitmapSsp.size);
            result.app_permissions.emplace_back(static_cast<ItsAid>(entry->psid), std::move(ssp));
        }
    }
    result.shared_at_request = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &iar.sharedAtRequest);
    if (iar.ecSignature.present == Vanetza_Security_EcSignature_PR_encryptedEcSignature) {
        result.ec_signature_encrypted = true;
        result.ec_signature = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &iar.ecSignature.choice.encryptedEcSignature);
    } else if (iar.ecSignature.present == Vanetza_Security_EcSignature_PR_ecSignature) {
        result.ec_signature_encrypted = false;
        result.ec_signature = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &iar.ecSignature.choice.ecSignature);
    } else {
        return std::nullopt;
    }
    return result;
}

bool validate_entitlement(Backend& backend, pki::EciesBackend& ecies, const Credential& ea, const PrivateKey& ea_encryption_key,
                          const ParsedAuthorizationRequest& req, const Certificate& candidate_ec) {
    ByteBuffer ec_signed_bytes;
    if (req.ec_signature_encrypted) {
        auto decrypted = pki::decrypt_as_recipient(backend, ecies, ea.certificate, ea_encryption_key, req.ec_signature);
        if (!decrypted) return false;
        ec_signed_bytes = *decrypted;
    } else {
        ec_signed_bytes = req.ec_signature;
    }
    // SignedExternalPayload: the visible payload is empty, the signed hash covers the SharedAtRequest
    auto external = pki::verify_signed(backend, ec_signed_bytes, nullptr, &candidate_ec, aid::SCR);
    if (!external || !external->empty()) return false;
    v3::SecuredMessage ext;
    if (!ext.decode(ec_signed_bytes)) return false;
    const auto* hashed = ext->content->choice.signedData->tbsData->payload->extDataHash;
    if (!hashed || hashed->present != Vanetza_Security_HashedData_PR_sha256HashedData || hashed->choice.sha256HashedData.size != 32)
        return false;
    const auto shared_hash = calculate_sha256_digest(req.shared_at_request.data(), req.shared_at_request.size());
    return std::memcmp(hashed->choice.sha256HashedData.buf, shared_hash.data(), 32) == 0;
}

} // namespace vidf_test
