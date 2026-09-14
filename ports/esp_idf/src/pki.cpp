// TS 102 941 V2.2.1 enrolment/authorization messages on the upstream
// EtsiTs103097Data wrapper. See pki.hpp for the clause map.
#include <vanetza_idf/pki.hpp>
#include <vanetza_idf/ecc.hpp>
#include <vanetza_idf/security.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/CtlCommand.h>
#include <vanetza/asn1/security/CtlEntry.h>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/asn1/security/InnerAtRequest.h>
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/asn1/security/PublicEncryptionKey.h>
#include <vanetza/asn1/security/PublicVerificationKey.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/asn1/security/ValidityPeriod.h>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <algorithm>
#include <cstring>

namespace vanetza_idf::pki {
using namespace vanetza;
using namespace vanetza::security;
using SecuredData = v3::SecuredMessage; // EtsiTs103097Data wrapper
namespace {

constexpr std::size_t aes_key_length = 16;
constexpr std::size_t nonce_length = 12;
constexpr std::size_t tag_length = 16;

ByteBuffer octets(const OCTET_STRING_t& s) { return ByteBuffer(s.buf, s.buf + s.size); }

// EccP256CurvePoint -> PublicKey (x-only points carry no usable y and are refused)
std::optional<PublicKey> point_to_key(const Vanetza_Security_EccP256CurvePoint& point, KeyType type) {
    PublicKey key;
    key.type = type;
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            key.compression = KeyCompression::Y0; key.x = octets(point.choice.compressed_y_0); break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            key.compression = KeyCompression::Y1; key.x = octets(point.choice.compressed_y_1); break;
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            key.compression = KeyCompression::NoCompression;
            key.x = octets(point.choice.uncompressedP256.x); key.y = octets(point.choice.uncompressedP256.y); break;
        default: return std::nullopt;
    }
    if (key.x.size() != 32) return std::nullopt;
    return key;
}

// uncompressed form for backends that need y (ECDH peer key)
std::optional<PublicKey> uncompressed(const PublicKey& key) {
    if (key.compression == KeyCompression::NoCompression) return key;
    auto point = ecc::decompress(key.type, key.x, key.compression == KeyCompression::Y1);
    if (!point) return std::nullopt;
    PublicKey out = key;
    out.compression = KeyCompression::NoCompression;
    out.y = point->y;
    return out;
}

PublicKey compressed(const PublicKey& key) {
    if (key.compression != KeyCompression::NoCompression || key.y.empty()) return key;
    PublicKey out = key;
    out.compression = (key.y.back() & 1) ? KeyCompression::Y1 : KeyCompression::Y0;
    out.y.clear();
    return out;
}

void fill_point(Vanetza_Security_EccP256CurvePoint& point, const PublicKey& key) {
    point = v3::to_asn1(make_ecc_point(compressed(key)));
}

void fill_verification_key(Vanetza_Security_PublicVerificationKey& out, const PublicKey& key) {
    if (key.type == KeyType::BrainpoolP256r1) {
        out.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
        fill_point(out.choice.ecdsaBrainpoolP256r1, key);
    } else {
        out.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
        fill_point(out.choice.ecdsaNistP256, key);
    }
}

void fill_encryption_key(Vanetza_Security_PublicEncryptionKey& out, const PublicKey& key) {
    out.supportedSymmAlg = Vanetza_Security_SymmAlgorithm_aes128Ccm;
    if (key.type == KeyType::BrainpoolP256r1) {
        out.publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesBrainpoolP256r1;
        fill_point(out.publicKey.choice.eciesBrainpoolP256r1, key);
    } else {
        out.publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
        fill_point(out.publicKey.choice.eciesNistP256, key);
    }
}

void fill_permissions(Vanetza_Security_CertificateSubjectAttributes& attributes, const Permissions& permissions) {
    if (permissions.empty()) return;
    attributes.appPermissions = v3::asn1::allocate<Vanetza_Security_SequenceOfPsidSsp>();
    for (const auto& permission : permissions) {
        auto* entry = v3::asn1::allocate<Vanetza_Security_PsidSsp>();
        entry->psid = permission.first;
        if (!permission.second.empty()) {
            entry->ssp = v3::asn1::allocate<Vanetza_Security_ServiceSpecificPermissions>();
            entry->ssp->present = Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp;
            v3::assign(&entry->ssp->choice.bitmapSsp, permission.second);
        }
        ASN_SEQUENCE_ADD(attributes.appPermissions, entry);
    }
}

// IEEE 1609.2 clause 5.3.1: Hash(Hash(tbsData) || Hash(signer certificate or empty string))
ByteBuffer message_digest(Backend& backend, HashAlgorithm hash, const ByteBuffer& tbs, const Certificate* signer) {
    if (signer) return v3::calculate_message_hash(backend, hash, tbs, *signer);
    ByteBuffer concat = backend.calculate_hash(hash, tbs);
    const ByteBuffer empty = backend.calculate_hash(hash, ByteBuffer {});
    concat.insert(concat.end(), empty.begin(), empty.end());
    return backend.calculate_hash(hash, concat);
}

// Fill the common header of a signed structure (TS 102 941: psid 623, generationTime only).
void prepare_signed(SecuredData& data, HashAlgorithm hash, Clock::time_point now, const Certificate* signer) {
    data.set_hash_id(hash);
    data.set_its_aid(aid::SCR);
    data.set_generation_time(v2::convert_time64(now));
    if (signer) {
        const auto digest = signer->calculate_digest();
        if (digest) data.set_signer_identifier(*digest); else data.set_signer_identifier_self();
    } else {
        data.set_signer_identifier_self();
    }
}

std::optional<ByteBuffer> finish_signed(Backend& backend, SecuredData& data, HashAlgorithm hash, const PrivateKey& key,
                                        const Certificate* signer) {
    try {
        const auto digest = message_digest(backend, hash, data.signing_payload(), signer);
        data.set_signature(backend.sign_digest(key, digest));
        return data.encode();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

ByteBuffer psk_id_input(const std::array<std::uint8_t, aes_key_length>& key) {
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_SymmetricEncryptionKey> wrapper(asn_DEF_Vanetza_Security_SymmetricEncryptionKey);
    wrapper->present = Vanetza_Security_SymmetricEncryptionKey_PR_aes128Ccm;
    OCTET_STRING_fromBuf(&wrapper->choice.aes128Ccm, reinterpret_cast<const char*>(key.data()), key.size());
    return wrapper.encode();
}

std::array<std::uint8_t, 16> left16(const ByteBuffer& in) {
    std::array<std::uint8_t, 16> out {};
    std::copy_n(in.begin(), std::min<std::size_t>(16, in.size()), out.begin());
    return out;
}

// InnerEcResponse / InnerAtResponse share the layout: requestHash, responseCode, certificate OPTIONAL
template<class Inner>
Result read_inner_response(const Inner& inner, const RequestContext& context, std::uint8_t& code,
                           std::optional<Certificate>& certificate) {
    certificate.reset();
    if (inner.requestHash.size != 16 || std::memcmp(inner.requestHash.buf, context.request_hash.data(), 16) != 0)
        return Result::rejected; // the response answers another request
    code = static_cast<std::uint8_t>(inner.responseCode);
    if (inner.certificate) {
        // asn1c forward-declares a distinct struct tag for this member; the object it points to is
        // decoded with asn_DEF_Vanetza_Security_EtsiTs103097Certificate, i.e. an EtsiTs103097Certificate_t.
        Certificate cert(*reinterpret_cast<const Vanetza_Security_EtsiTs103097Certificate_t*>(inner.certificate));
        if (!cert.validate()) return Result::rejected;
        certificate = std::move(cert);
    } else if (code == 0) {
        return Result::rejected; // clause 6.2.3.2.2: a positive response returns a certificate
    }
    return Result::accepted;
}

// Decrypt, verify the authority signature and hand back the EtsiTs102941Data
std::optional<ByteBuffer> open_response(Backend& backend, EciesBackend& ecies, const RequestContext& context,
                                        const Certificate& authority, const ByteBuffer& encoded) {
    auto signed_bytes = decrypt_with_psk(ecies, context.aes_key, encoded);
    if (!signed_bytes) return std::nullopt;
    return verify_signed(backend, *signed_bytes, nullptr, &authority, aid::SCR);
}
} // namespace

ByteBuffer kdf2_sha256(Backend& backend, const ByteBuffer& shared_secret, const ByteBuffer& kdp, std::size_t length) {
    ByteBuffer derived;
    for (std::uint32_t counter = 1; derived.size() < length; ++counter) {
        ByteBuffer input = shared_secret;
        input.push_back(static_cast<std::uint8_t>(counter >> 24));
        input.push_back(static_cast<std::uint8_t>(counter >> 16));
        input.push_back(static_cast<std::uint8_t>(counter >> 8));
        input.push_back(static_cast<std::uint8_t>(counter));
        input.insert(input.end(), kdp.begin(), kdp.end());
        const auto block = backend.calculate_hash(HashAlgorithm::SHA256, input);
        derived.insert(derived.end(), block.begin(), block.end());
    }
    derived.resize(length);
    return derived;
}

std::optional<EncryptedKey> ecies_encrypt_key(Backend& backend, EciesBackend& ecies, const PublicKey& recipient,
                                              const ByteBuffer& p1, const std::array<std::uint8_t, 16>& aes_key) {
    const auto peer = uncompressed(recipient);
    if (!peer || (peer->type != KeyType::NistP256 && peer->type != KeyType::BrainpoolP256r1)) return std::nullopt;
    try {
        const KeyPair ephemeral = ecies.generate_key(peer->type);
        const auto secret = ecies.ecdh_x(ephemeral.priv, *peer);
        if (!secret) return std::nullopt;
        // K1 (16 octets, key encryption) || K2 (32 octets, MAC key)
        const ByteBuffer k = kdf2_sha256(backend, *secret, p1, aes_key_length + 32);
        EncryptedKey out;
        out.v = ephemeral.pub;
        ByteBuffer c(aes_key_length);
        for (std::size_t i = 0; i < aes_key_length; ++i) c[i] = k[i] ^ aes_key[i];
        const ByteBuffer k2(k.begin() + aes_key_length, k.end());
        const ByteBuffer tag = ecies.hmac_sha256(k2, c);
        if (tag.size() < tag_length) return std::nullopt;
        out.c = left16(c);
        out.t = left16(tag);
        return out;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::array<std::uint8_t, 16>> ecies_decrypt_key(Backend& backend, EciesBackend& ecies,
                                                              const PrivateKey& recipient, const ByteBuffer& p1,
                                                              const EncryptedKey& encrypted) {
    const auto peer = uncompressed(encrypted.v);
    if (!peer) return std::nullopt;
    try {
        const auto secret = ecies.ecdh_x(recipient, *peer);
        if (!secret) return std::nullopt;
        const ByteBuffer k = kdf2_sha256(backend, *secret, p1, aes_key_length + 32);
        const ByteBuffer c(encrypted.c.begin(), encrypted.c.end());
        const ByteBuffer k2(k.begin() + aes_key_length, k.end());
        const ByteBuffer tag = ecies.hmac_sha256(k2, c);
        if (tag.size() < tag_length) return std::nullopt;
        // constant-time comparison of the truncated tag
        unsigned diff = 0;
        for (std::size_t i = 0; i < tag_length; ++i) diff |= tag[i] ^ encrypted.t[i];
        if (diff != 0) return std::nullopt;
        std::array<std::uint8_t, 16> key {};
        for (std::size_t i = 0; i < aes_key_length; ++i) key[i] = k[i] ^ encrypted.c[i];
        return key;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ---- building blocks -------------------------------------------------------

std::optional<ByteBuffer> sign_data(Backend& backend, Clock::time_point now, HashAlgorithm hash, const ByteBuffer& payload,
                                    const PrivateKey& key, const Certificate* signer) {
    SecuredData data = SecuredData::with_signed_data();
    prepare_signed(data, hash, now, signer);
    data.set_payload(payload);
    return finish_signed(backend, data, hash, key, signer);
}

std::optional<ByteBuffer> sign_external(Backend& backend, Clock::time_point now, const ByteBuffer& external_payload,
                                        const PrivateKey& key, const Certificate& signer) {
    SecuredData data = SecuredData::with_signed_data_hash();
    prepare_signed(data, HashAlgorithm::SHA256, now, &signer);
    data.set_external_payload_hash(calculate_sha256_digest(external_payload.data(), external_payload.size()));
    return finish_signed(backend, data, HashAlgorithm::SHA256, key, &signer);
}

std::optional<ByteBuffer> encrypt_for(Backend& backend, EciesBackend& ecies, const Certificate& recipient,
                                      const ByteBuffer& plaintext, std::array<std::uint8_t, 16>& aes_key) {
    const auto encryption_key = v3::get_public_encryption_key(*recipient.content());
    const auto recipient_id = recipient.calculate_digest();
    if (!encryption_key || !recipient_id) return std::nullopt;
    try {
        const ByteBuffer random = ecies.random(aes_key_length + nonce_length);
        std::array<std::uint8_t, nonce_length> nonce {};
        std::copy_n(random.begin(), aes_key_length, aes_key.begin());
        std::copy_n(random.begin() + aes_key_length, nonce_length, nonce.begin());
        ByteBuffer ciphertext;
        if (!ecies.aes_ccm_encrypt(aes_key, nonce, plaintext, ciphertext)) return std::nullopt;
        // P1 = SHA-256 of the recipient certificate (IEEE 1609.2 clause 5.3.5, certRecipInfo)
        const ByteBuffer p1 = backend.calculate_hash(HashAlgorithm::SHA256, recipient.encode());
        const auto wrapped = ecies_encrypt_key(backend, ecies, *encryption_key, p1, aes_key);
        if (!wrapped) return std::nullopt;
        SecuredData data = SecuredData::with_encrypted_data();
        data.set_aes_ccm_ciphertext(ciphertext, nonce);
        data.set_cert_recip_info(*recipient_id, wrapped->c, wrapped->t, compressed(wrapped->v));
        return data.encode();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ByteBuffer> encrypt_with_psk(EciesBackend& ecies, const std::array<std::uint8_t, 16>& aes_key,
                                           const ByteBuffer& plaintext) {
    try {
        const ByteBuffer random = ecies.random(nonce_length);
        std::array<std::uint8_t, nonce_length> nonce {};
        std::copy_n(random.begin(), nonce_length, nonce.begin());
        ByteBuffer ciphertext;
        if (!ecies.aes_ccm_encrypt(aes_key, nonce, plaintext, ciphertext)) return std::nullopt;
        SecuredData data = SecuredData::with_encrypted_data();
        data.set_aes_ccm_ciphertext(ciphertext, nonce);
        // pskRecipInfo = HashedId8 of the COER SymmetricEncryptionKey (IEEE 1609.2 clause 6.3.43)
        const ByteBuffer key_encoding = psk_id_input(aes_key);
        const HashedId8 psk_id = create_hashed_id8(calculate_sha256_digest(key_encoding.data(), key_encoding.size()));
        auto* recipient = v3::asn1::allocate<Vanetza_Security_RecipientInfo>();
        recipient->present = Vanetza_Security_RecipientInfo_PR_pskRecipInfo;
        OCTET_STRING_fromBuf(&recipient->choice.pskRecipInfo, reinterpret_cast<const char*>(psk_id.data()), psk_id.size());
        ASN_SEQUENCE_ADD(&data->content->choice.encryptedData.recipients.list, recipient);
        return data.encode();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ByteBuffer> decrypt_as_recipient(Backend& backend, EciesBackend& ecies, const Certificate& recipient,
                                               const PrivateKey& encryption_key, const ByteBuffer& encoded,
                                               std::array<std::uint8_t, 16>* aes_key_out) {
    SecuredData data;
    if (!data.decode(encoded) || !data.is_encrypted()) return std::nullopt;
    const auto own_id = recipient.calculate_digest();
    if (!own_id) return std::nullopt;
    const auto& recipients = data->content->choice.encryptedData.recipients.list;
    for (int i = 0; i < recipients.count; ++i) {
        const auto* info = recipients.array[i];
        if (!info || info->present != Vanetza_Security_RecipientInfo_PR_certRecipInfo) continue;
        const auto& cert_info = info->choice.certRecipInfo;
        if (cert_info.recipientId.size != 8 || std::memcmp(cert_info.recipientId.buf, own_id->data(), 8) != 0) continue;
        const Vanetza_Security_EciesP256EncryptedKey* ecies_key = nullptr;
        KeyType type = KeyType::NistP256;
        if (cert_info.encKey.present == Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesNistP256) {
            ecies_key = &cert_info.encKey.choice.eciesNistP256;
        } else if (cert_info.encKey.present == Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesBrainpoolP256r1) {
            ecies_key = &cert_info.encKey.choice.eciesBrainpoolP256r1;
            type = KeyType::BrainpoolP256r1;
        } else {
            continue;
        }
        if (ecies_key->c.size != 16 || ecies_key->t.size != 16) continue;
        EncryptedKey wrapped;
        auto v = point_to_key(ecies_key->v, type);
        if (!v) continue;
        wrapped.v = *v;
        std::copy_n(ecies_key->c.buf, 16, wrapped.c.begin());
        std::copy_n(ecies_key->t.buf, 16, wrapped.t.begin());
        const ByteBuffer p1 = backend.calculate_hash(HashAlgorithm::SHA256, recipient.encode());
        const auto aes_key = ecies_decrypt_key(backend, ecies, encryption_key, p1, wrapped);
        if (!aes_key) return std::nullopt;
        ByteBuffer ciphertext;
        std::array<std::uint8_t, nonce_length> nonce {};
        data.get_aes_ccm_ciphertext(ciphertext, nonce);
        ByteBuffer plaintext;
        if (!ecies.aes_ccm_decrypt(*aes_key, nonce, ciphertext, plaintext)) return std::nullopt;
        if (aes_key_out) *aes_key_out = *aes_key;
        return plaintext;
    }
    return std::nullopt;
}

std::optional<ByteBuffer> decrypt_with_psk(EciesBackend& ecies, const std::array<std::uint8_t, 16>& aes_key,
                                           const ByteBuffer& encoded) {
    SecuredData data;
    if (!data.decode(encoded) || !data.is_encrypted()) return std::nullopt;
    if (!data.check_psk_match(aes_key)) return std::nullopt; // response is not for this request
    ByteBuffer ciphertext;
    std::array<std::uint8_t, nonce_length> nonce {};
    data.get_aes_ccm_ciphertext(ciphertext, nonce);
    ByteBuffer plaintext;
    if (!ecies.aes_ccm_decrypt(aes_key, nonce, ciphertext, plaintext)) return std::nullopt;
    return plaintext;
}

std::optional<ByteBuffer> verify_signed(Backend& backend, const ByteBuffer& encoded, const PublicKey* self_key,
                                        const Certificate* signer, ItsAid expected_psid) {
    SecuredData data;
    if (!data.decode(encoded) || !data.is_signed() || data.protocol_version() != 3) return std::nullopt;
    if (data.its_aid() != expected_psid || !data.generation_time()) return std::nullopt;
    const auto hash = data.hash_id();
    const auto signature = data.signature();
    if (hash == HashAlgorithm::Unspecified || !signature) return std::nullopt;
    const auto* signed_data = data->content->choice.signedData;
    PublicKey key;
    if (signer) {
        const auto digest = signer->calculate_digest();
        if (signed_data->signer.present != Vanetza_Security_SignerIdentifier_PR_digest || !digest ||
            signed_data->signer.choice.digest.size != 8 ||
            std::memcmp(signed_data->signer.choice.digest.buf, digest->data(), 8) != 0) return std::nullopt;
        const auto signer_key = v3::get_public_key(*signer->content());
        if (!signer_key) return std::nullopt;
        key = *signer_key;
    } else {
        if (signed_data->signer.present != Vanetza_Security_SignerIdentifier_PR_self || !self_key) return std::nullopt;
        key = *self_key;
    }
    const auto digest = message_digest(backend, hash, data.signing_payload(), signer);
    if (!backend.verify_digest(key, digest, *signature)) return std::nullopt;
    auto payload = data.payload();
    const auto& packet = boost::get<CohesivePacket>(payload);
    const auto view = create_byte_view(packet, OsiLayer::Network, max_osi_layer());
    return ByteBuffer(view.begin(), view.end());
}

// ---- TS 102 941 clause 6.2.3.2 --------------------------------------------------

Result build_enrolment_request(Backend& backend, EciesBackend& ecies, Clock::time_point now,
                               const EnrolmentRequestParameters& params, const Certificate& ea, ByteBuffer& encoded,
                               RequestContext& context) {
    if (params.its_id.empty() || params.verification_key.priv.key.empty() || params.outer_signer_key.key.empty())
        return Result::invalid_argument;
    if (!v3::get_public_encryption_key(*ea.content())) return Result::invalid_argument;
    // 1. InnerEcRequest (certificateFormat ts103097v131 = 1)
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    v3::assign(&inner->itsId, params.its_id);
    inner->certificateFormat = Vanetza_Security_CertificateFormat_ts103097v131;
    fill_verification_key(inner->publicKeys.verificationKey, params.verification_key.pub);
    fill_permissions(inner->requestedSubjectAttributes, params.app_permissions);
    if (!inner.validate()) return Result::invalid_argument;
    // 2. InnerEcRequestSignedForPop: self-signed with the new verification key
    auto pop = sign_data(backend, now, params.hash, inner.encode(), params.verification_key.priv, nullptr);
    if (!pop) return Result::security_unavailable;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest;
    void* target = &mgmt->content.choice.enrolmentRequest;
    if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &target, *pop)) return Result::security_unavailable;
    // 3. Outer EtsiTs103097Data-Signed: self (canonical key) or digest of the current EC
    auto outer = sign_data(backend, now, params.hash, mgmt.encode(), params.outer_signer_key, params.current_ec);
    if (!outer) return Result::security_unavailable;
    // 4. EtsiTs103097Data-Encrypted for the EA
    auto encrypted = encrypt_for(backend, ecies, ea, *outer, context.aes_key);
    if (!encrypted) return Result::security_unavailable;
    encoded = std::move(*encrypted);
    context.request_hash = left16(backend.calculate_hash(HashAlgorithm::SHA256, encoded));
    return Result::accepted;
}

Result parse_enrolment_response(Backend& backend, EciesBackend& ecies, const RequestContext& context, const Certificate& ea,
                                const ByteBuffer& encoded, EnrolmentResponse& out) {
    auto mgmt_bytes = open_response(backend, ecies, context, ea, encoded);
    if (!mgmt_bytes) return Result::rejected;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(*mgmt_bytes) || mgmt->version != Vanetza_Security_Version_v1 ||
        mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse) return Result::rejected;
    return read_inner_response(mgmt->content.choice.enrolmentResponse, context, out.response_code, out.certificate);
}

// ---- TS 102 941 clause 6.2.3.3 --------------------------------------------------

Result build_authorization_request(Backend& backend, EciesBackend& ecies, Clock::time_point now,
                                   const AuthorizationRequestParameters& params, const Certificate& ea,
                                   const Certificate& aa, ByteBuffer& encoded, RequestContext& context) {
    if (!params.ec || params.ec_key.key.empty() || params.verification_key.priv.key.empty() || params.app_permissions.empty())
        return Result::invalid_argument;
    if (params.hash != HashAlgorithm::SHA256) return Result::unsupported; // extDataHash carries sha256HashedData
    if (!v3::get_public_encryption_key(*aa.content()) || (params.privacy && !v3::get_public_encryption_key(*ea.content())))
        return Result::invalid_argument;
    const auto ea_id = ea.calculate_digest();
    if (!ea_id) return Result::invalid_argument;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest;
    auto& inner = mgmt->content.choice.authorizationRequest;
    // publicKeys: new verification key and optional encryption key
    fill_verification_key(inner.publicKeys.verificationKey, params.verification_key.pub);
    if (params.encryption_key) {
        inner.publicKeys.encryptionKey = v3::asn1::allocate<Vanetza_Security_PublicEncryptionKey>();
        fill_encryption_key(*inner.publicKeys.encryptionKey, params.encryption_key->pub);
    }
    // hmacKey: 32 random octets; keyTag = leftmost 16 octets of HMAC-SHA256(hmacKey, OER(publicKeys))
    ByteBuffer hmac_key;
    try { hmac_key = ecies.random(32); } catch (const std::exception&) { return Result::security_unavailable; }
    if (hmac_key.size() != 32) return Result::security_unavailable;
    v3::assign(&inner.hmacKey, hmac_key);
    ByteBuffer tag_input = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &inner.publicKeys.verificationKey);
    if (inner.publicKeys.encryptionKey) {
        const auto enc = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_PublicEncryptionKey, inner.publicKeys.encryptionKey);
        tag_input.insert(tag_input.end(), enc.begin(), enc.end());
    }
    const auto key_tag = ecies.hmac_sha256(hmac_key, tag_input);
    if (key_tag.size() < 16) return Result::security_unavailable;
    // SharedAtRequest
    auto& shared = inner.sharedAtRequest;
    OCTET_STRING_fromBuf(&shared.eaId, reinterpret_cast<const char*>(ea_id->data()), ea_id->size());
    OCTET_STRING_fromBuf(&shared.keyTag, reinterpret_cast<const char*>(key_tag.data()), 16);
    shared.certificateFormat = Vanetza_Security_CertificateFormat_ts103097v131;
    fill_permissions(shared.requestedSubjectAttributes, params.app_permissions);
    if (params.validity_period) {
        shared.requestedSubjectAttributes.validityPeriod = v3::asn1::allocate<Vanetza_Security_ValidityPeriod>();
        shared.requestedSubjectAttributes.validityPeriod->start = v2::convert_time32(params.validity_period->first);
        shared.requestedSubjectAttributes.validityPeriod->duration.present = Vanetza_Security_Duration_PR_hours;
        shared.requestedSubjectAttributes.validityPeriod->duration.choice.hours = params.validity_period->second;
    }
    // EC signature over the SharedAtRequest (external payload), signer = digest of the EC
    const ByteBuffer shared_encoded = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &shared);
    auto ec_signed = sign_external(backend, now, shared_encoded, params.ec_key, *params.ec);
    if (!ec_signed) return Result::security_unavailable;
    ByteBuffer ec_signature_bytes;
    if (params.privacy) {
        std::array<std::uint8_t, 16> throwaway {};
        auto encrypted = encrypt_for(backend, ecies, ea, *ec_signed, throwaway);
        if (!encrypted) return Result::security_unavailable;
        inner.ecSignature.present = Vanetza_Security_EcSignature_PR_encryptedEcSignature;
        void* target = &inner.ecSignature.choice.encryptedEcSignature;
        if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &target, *encrypted)) return Result::security_unavailable;
    } else {
        inner.ecSignature.present = Vanetza_Security_EcSignature_PR_ecSignature;
        void* target = &inner.ecSignature.choice.ecSignature;
        if (!vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Data, &target, *ec_signed)) return Result::security_unavailable;
    }
    if (!mgmt.validate()) return Result::security_unavailable;
    ByteBuffer plaintext = mgmt.encode();
    if (params.include_pop) {
        auto pop = sign_data(backend, now, params.hash, plaintext, params.verification_key.priv, nullptr);
        if (!pop) return Result::security_unavailable;
        plaintext = std::move(*pop);
    } else {
        // EtsiTs103097Data unsecured envelope around the EtsiTs102941Data
        SecuredData envelope;
        envelope->protocolVersion = 3;
        envelope->content = v3::asn1::allocate<Vanetza_Security_Ieee1609Dot2Content>();
        envelope->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
        v3::assign(&envelope->content->choice.unsecuredData, plaintext);
        plaintext = envelope.encode();
    }
    auto encrypted = encrypt_for(backend, ecies, aa, plaintext, context.aes_key);
    if (!encrypted) return Result::security_unavailable;
    encoded = std::move(*encrypted);
    context.request_hash = left16(backend.calculate_hash(HashAlgorithm::SHA256, encoded));
    return Result::accepted;
}

Result parse_authorization_response(Backend& backend, EciesBackend& ecies, const RequestContext& context, const Certificate& aa,
                                    const ByteBuffer& encoded, AuthorizationResponse& out) {
    auto mgmt_bytes = open_response(backend, ecies, context, aa, encoded);
    if (!mgmt_bytes) return Result::rejected;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(*mgmt_bytes) || mgmt->version != Vanetza_Security_Version_v1 ||
        mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse) return Result::rejected;
    return read_inner_response(mgmt->content.choice.authorizationResponse, context, out.response_code, out.certificate);
}

// ---- TS 102 941 clause 6.3: RCA trust list and revocation list -----------------------

namespace {
void set_url(Vanetza_Security_Url_t& url, const std::string& text) {
    OCTET_STRING_fromBuf(&url, text.data(), text.size());
}
std::string get_url(const Vanetza_Security_Url_t& url) {
    return std::string(reinterpret_cast<const char*>(url.buf), url.size);
}
void set_hashed_id8(Vanetza_Security_HashedId8_t& target, const HashedId8& id) {
    OCTET_STRING_fromBuf(&target, reinterpret_cast<const char*>(id.data()), id.size());
}
std::optional<HashedId8> get_hashed_id8(const Vanetza_Security_HashedId8_t& source) {
    if (source.size != 8) return std::nullopt;
    HashedId8 id;
    std::copy_n(source.buf, 8, id.begin());
    return id;
}
// the certificate structure of an entry, decoded from COER into the inline member
bool put_certificate(Vanetza_Security_EtsiTs103097Certificate_t& target, const ByteBuffer& coer) {
    void* into = &target;
    return vanetza::asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &into, coer);
}

// EtsiTs102941Data{content} signed by the RCA with the signer certificate inline (clause 6.3.4)
std::optional<ByteBuffer> sign_list(Backend& backend, Clock::time_point now, const Certificate& rca, const PrivateKey& rca_key,
                                    ItsAid psid, const ByteBuffer& mgmt) {
    if (!rca.valid_for_application(psid)) return std::nullopt; // TS 103 097 clause 7.2.3: CRL/CTL appPermissions
    SecuredData data = SecuredData::with_signed_data();
    data.set_hash_id(HashAlgorithm::SHA256);
    data.set_its_aid(psid);
    data.set_generation_time(v2::convert_time64(now));
    data.set_signer_identifier(rca);
    data.set_payload(mgmt);
    return finish_signed(backend, data, HashAlgorithm::SHA256, rca_key, &rca);
}

// the EtsiTs102941Data of a list message that verifies as signed by rca with the given psid
std::optional<ByteBuffer> open_list(Backend& backend, const ByteBuffer& message, const Certificate& rca, ItsAid psid) {
    SecuredData data;
    if (!data.decode(message) || !data.is_signed() || data.protocol_version() != 3) return std::nullopt;
    if (data.its_aid() != psid || !data.generation_time() || data.hash_id() != HashAlgorithm::SHA256) return std::nullopt;
    if (!rca.valid_for_application(psid)) return std::nullopt;
    // clause 6.3.4: the signer contains the issuer's certificate; it must be the RCA we trust
    const auto* signed_data = data->content->choice.signedData;
    if (signed_data->signer.present != Vanetza_Security_SignerIdentifier_PR_certificate ||
        signed_data->signer.choice.certificate.list.count != 1) return std::nullopt;
    const ByteBuffer inline_cert = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate,
                                                            signed_data->signer.choice.certificate.list.array[0]);
    if (inline_cert != rca.encode()) return std::nullopt;
    const auto signature = data.signature();
    const auto key = v3::get_public_key(*rca.content());
    if (!signature || !key) return std::nullopt;
    const auto digest = message_digest(backend, HashAlgorithm::SHA256, data.signing_payload(), &rca);
    try {
        if (!backend.verify_digest(*key, digest, *signature)) return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    auto payload = data.payload();
    const auto& packet = boost::get<CohesivePacket>(payload);
    const auto view = create_byte_view(packet, OsiLayer::Network, max_osi_layer());
    return ByteBuffer(view.begin(), view.end());
}
} // namespace

std::optional<ByteBuffer> build_rca_ctl(Backend& backend, Clock::time_point now, const Certificate& rca, const PrivateKey& rca_key,
                                        const TrustListEntries& entries, Time32 next_update, std::uint8_t ctl_sequence) {
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca;
    auto& ctl = mgmt->content.choice.certificateTrustListRca;
    ctl.version = 1; // clause 6.3.4: CtlFormat version 1
    ctl.nextUpdate = next_update;
    ctl.isFullCtl = 1;
    ctl.ctlSequence = ctl_sequence;
    const auto add = [&](Vanetza_Security_CtlEntry_PR kind) -> Vanetza_Security_CtlEntry_t& {
        auto* command = vanetza::asn1::allocate<Vanetza_Security_CtlCommand_t>();
        command->present = Vanetza_Security_CtlCommand_PR_add;
        command->choice.add.present = kind;
        ASN_SEQUENCE_ADD(&ctl.ctlCommands, command);
        return command->choice.add;
    };
    for (const auto& ea : entries.ea) {
        auto& entry = add(Vanetza_Security_CtlEntry_PR_ea).choice.ea;
        if (!put_certificate(entry.eaCertificate, ea.certificate)) return std::nullopt;
        set_url(entry.aaAccessPoint, ea.access_point);
    }
    for (const auto& aa : entries.aa) {
        auto& entry = add(Vanetza_Security_CtlEntry_PR_aa).choice.aa;
        if (!put_certificate(entry.aaCertificate, aa.certificate)) return std::nullopt;
        set_url(entry.accessPoint, aa.access_point);
    }
    for (const auto& dc : entries.dc) {
        auto& entry = add(Vanetza_Security_CtlEntry_PR_dc).choice.dc;
        set_url(entry.url, dc.url);
        for (const auto& id : dc.certificates) {
            auto* item = vanetza::asn1::allocate<Vanetza_Security_HashedId8_t>();
            set_hashed_id8(*item, id);
            ASN_SEQUENCE_ADD(&entry.cert, item);
        }
    }
    if (!mgmt.validate()) return std::nullopt;
    return sign_list(backend, now, rca, rca_key, aid::CTL, mgmt.encode());
}

std::optional<ByteBuffer> build_crl(Backend& backend, Clock::time_point now, const Certificate& rca, const PrivateKey& rca_key,
                                    const std::vector<HashedId8>& revoked, Time32 this_update, Time32 next_update) {
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_certificateRevocationList;
    auto& crl = mgmt->content.choice.certificateRevocationList;
    crl.version = 1;
    crl.thisUpdate = this_update;
    crl.nextUpdate = next_update;
    for (const auto& id : revoked) {
        auto* entry = vanetza::asn1::allocate<Vanetza_Security_CrlEntry_t>();
        set_hashed_id8(*entry, id);
        ASN_SEQUENCE_ADD(&crl.entries, entry);
    }
    if (!mgmt.validate()) return std::nullopt;
    return sign_list(backend, now, rca, rca_key, aid::CRL, mgmt.encode());
}

std::optional<RcaTrustList> parse_rca_ctl(Backend& backend, const ByteBuffer& message, const Certificate& rca) {
    const auto mgmt_bytes = open_list(backend, message, rca, aid::CTL);
    if (!mgmt_bytes) return std::nullopt;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(*mgmt_bytes) || mgmt->version != Vanetza_Security_Version_v1 ||
        mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca) return std::nullopt;
    const auto& ctl = mgmt->content.choice.certificateTrustListRca;
    if (ctl.version != 1 || ctl.ctlSequence < 0 || ctl.ctlSequence > 255) return std::nullopt;
    RcaTrustList list;
    list.sequence = static_cast<std::uint8_t>(ctl.ctlSequence);
    list.next_update = static_cast<Time32>(ctl.nextUpdate);
    list.full = ctl.isFullCtl != 0;
    const auto rca_digest = rca.calculate_digest();
    if (!rca_digest) return std::nullopt;
    const auto issued_by_rca = [&](const Vanetza_Security_EtsiTs103097Certificate_t& raw, Certificate& out) {
        out = Certificate(raw);
        const auto issuer = out.issuer_digest();
        return issuer && *issuer == *rca_digest && out.is_ca_certificate() &&
               vanetza_idf::security::verify_certificate_signature(backend, out, &rca);
    };
    for (int i = 0; i < ctl.ctlCommands.list.count; ++i) {
        const auto* command = ctl.ctlCommands.list.array[i];
        if (!command) return std::nullopt;
        if (command->present == Vanetza_Security_CtlCommand_PR_add) {
            const auto& entry = command->choice.add;
            Certificate certificate;
            switch (entry.present) {
                case Vanetza_Security_CtlEntry_PR_ea:
                    if (!issued_by_rca(entry.choice.ea.eaCertificate, certificate)) return std::nullopt;
                    list.ea.push_back(std::move(certificate));
                    break;
                case Vanetza_Security_CtlEntry_PR_aa:
                    if (!issued_by_rca(entry.choice.aa.aaCertificate, certificate)) return std::nullopt;
                    list.aa.push_back(std::move(certificate));
                    break;
                case Vanetza_Security_CtlEntry_PR_dc: {
                    TrustListEntries::DistributionCentre dc;
                    dc.url = get_url(entry.choice.dc.url);
                    for (int k = 0; k < entry.choice.dc.cert.list.count; ++k) {
                        const auto id = entry.choice.dc.cert.list.array[k] ? get_hashed_id8(*entry.choice.dc.cert.list.array[k]) : std::nullopt;
                        if (!id) return std::nullopt;
                        dc.certificates.push_back(*id);
                    }
                    list.dc.push_back(std::move(dc));
                    break;
                }
                default:
                    return std::nullopt; // clause 6.3.2: an RCA CTL carries no RCA or TLM entries
            }
        } else if (command->present == Vanetza_Security_CtlCommand_PR_delete) {
            if (list.full) return std::nullopt; // clause 6.3.4: a FullCtl has add commands only
            const auto& del = command->choice.Delete;
            if (del.present == Vanetza_Security_CtlDelete_PR_cert) {
                const auto id = get_hashed_id8(del.choice.cert);
                if (!id) return std::nullopt;
                list.deleted.push_back(*id);
            } else if (del.present == Vanetza_Security_CtlDelete_PR_dc) {
                list.deleted_dc.push_back(get_url(del.choice.dc));
            } else {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
    return list;
}

std::optional<RevocationList> parse_crl(Backend& backend, const ByteBuffer& message, const Certificate& rca) {
    const auto mgmt_bytes = open_list(backend, message, rca, aid::CRL);
    if (!mgmt_bytes) return std::nullopt;
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (!mgmt.decode(*mgmt_bytes) || mgmt->version != Vanetza_Security_Version_v1 ||
        mgmt->content.present != Vanetza_Security_EtsiTs102941DataContent_PR_certificateRevocationList) return std::nullopt;
    const auto& crl = mgmt->content.choice.certificateRevocationList;
    if (crl.version != 1) return std::nullopt;
    RevocationList list;
    list.this_update = static_cast<Time32>(crl.thisUpdate);
    list.next_update = static_cast<Time32>(crl.nextUpdate);
    for (int i = 0; i < crl.entries.list.count; ++i) {
        const auto id = crl.entries.list.array[i] ? get_hashed_id8(*crl.entries.list.array[i]) : std::nullopt;
        if (!id) return std::nullopt;
        list.revoked.push_back(*id);
    }
    return list;
}

std::size_t apply(const RcaTrustList& list, vanetza_idf::security::TrustConfiguration& trust) {
    std::size_t added = 0;
    for (const auto* entries : {&list.ea, &list.aa}) {
        for (const auto& certificate : *entries) {
            if (trust.add_authority(certificate) == Result::accepted) ++added;
        }
    }
    return added;
}

std::size_t apply(const RevocationList& list, const Certificate& rca, vanetza_idf::security::TrustConfiguration& trust) {
    const auto issuer = rca.calculate_digest();
    if (!issuer) return 0;
    trust.clear_revocations(*issuer);
    for (const auto& id : list.revoked) trust.revoke(*issuer, id);
    return list.revoked.size();
}

} // namespace vanetza_idf::pki
