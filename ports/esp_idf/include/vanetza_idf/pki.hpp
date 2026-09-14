#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza_idf/security.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

/** TS 102 941 V2.2.1 enrolment and authorization request/response core.
 *
 * Clause 6.2.3.2 (EnrolmentRequest/Response) and clause 6.2.3.3
 * (AuthorizationRequest/Response with proof of possession), message formats
 * of Annex A.2, signed structures per TS 103 097 V2.2.1 clause 5.2 with
 * psid = secured certificate request (TS 102 965 V2.4.1 Table A.1, 623),
 * encryption per TS 103 097 clause 5.3: ECIES (IEEE Std 1609.2 clause 5.3.5,
 * KDF2 of IEEE Std 1363a, HMAC-SHA256 tag truncated to 128 bit, key
 * derivation parameter = SHA-256 of the recipient certificate) and
 * AES-128-CCM (IEEE Std 1609.2 clause 5.3.8: 12-octet nonce, 16-octet tag
 * appended to the ciphertext).
 *
 * The library builds and parses the messages only. Transport to the EA/AA
 * (TS 102 941 clause 6.1 reference points S3/S4, HTTP in practice) and the
 * retrieval of CTL and CRL from a distribution centre (clause 6.3.5, Annex D:
 * GET <dc>/getctl/<HashedId8>, GET <dc>/getcrl/<HashedId8>) are supplied by the
 * application; the lists themselves are built, verified and read here (clause
 * 6.3.2 to 6.3.6, formats of clause A.2.7 as compiled from the TS 102 941
 * V1.3.1 module, unchanged for these types in V2.2.1); butterfly keys (clause
 * 6.2.3.5) are not implemented.
 */
namespace vanetza_idf::pki {

using vanetza::ByteBuffer;
using vanetza::security::HashAlgorithm;
using vanetza::security::HashedId8;
using vanetza::security::KeyType;
using vanetza::security::PrivateKey;
using vanetza::security::PublicKey;
using vanetza::security::v3::Certificate;

/// A verification or encryption key pair (IEEE Std 1609.2 PublicVerificationKey /
/// BasePublicEncryptionKey, TS 103 097 V2.2.1 clause 6): private scalar and the
/// uncompressed public point of the same curve.
struct KeyPair {
    PrivateKey priv;
    PublicKey pub; // uncompressed
};

/** Primitives beyond vanetza::security::Backend that ECIES and AES-CCM need.
 * Implemented on OpenSSL (host) and the PSA Crypto API (device). */
class EciesBackend {
public:
    virtual ~EciesBackend() = default;
    /// fresh key pair on the given curve (NIST P-256 or brainpoolP256r1 for ECIES)
    virtual KeyPair generate_key(KeyType) = 0;
    /// x coordinate of the ECDH shared point (IEEE 1609.2 5.3.5: the shared secret value)
    virtual std::optional<ByteBuffer> ecdh_x(const PrivateKey& own, const PublicKey& peer) = 0;
    /// HMAC-SHA256 (FIPS PUB 198-1), full 32-octet tag
    virtual ByteBuffer hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) = 0;
    /// cryptographically strong random octets
    virtual ByteBuffer random(std::size_t octets) = 0;
    /// AES-128-CCM, 12-octet nonce, no associated data; output = ciphertext || 16-octet tag
    virtual bool aes_ccm_encrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                 const ByteBuffer& plaintext, ByteBuffer& ciphertext_and_tag) = 0;
    virtual bool aes_ccm_decrypt(const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 12>& nonce,
                                 const ByteBuffer& ciphertext_and_tag, ByteBuffer& plaintext) = 0;
};

/// IEEE 1609.2 clause 6.3.36 EciesP256EncryptedKey: ephemeral point v, wrapped key c, tag t
struct EncryptedKey {
    PublicKey v;
    std::array<std::uint8_t, 16> c;
    std::array<std::uint8_t, 16> t;
};

/// KDF2 (IEEE 1363a-2004 clause 13.2 with SHA-256): counter starts at 1, big-endian
ByteBuffer kdf2_sha256(vanetza::security::Backend&, const ByteBuffer& shared_secret, const ByteBuffer& kdp, std::size_t length);

/// ECIES encryption of a 16-octet AES key for a recipient public key; p1 = key derivation parameter
std::optional<EncryptedKey> ecies_encrypt_key(vanetza::security::Backend&, EciesBackend&, const PublicKey& recipient,
                                              const ByteBuffer& p1, const std::array<std::uint8_t, 16>& aes_key);
/// ECIES decryption with the recipient private key; none when the tag does not verify
std::optional<std::array<std::uint8_t, 16>> ecies_decrypt_key(vanetza::security::Backend&, EciesBackend&,
                                                              const PrivateKey& recipient, const ByteBuffer& p1,
                                                              const EncryptedKey&);

/** State kept from a request for reading its response: the AES key (the response is
 * encrypted with it, referenced by pskRecipInfo) and the request hash the response
 * must echo (left-most 16 octets of SHA-256 of the encrypted request). */
struct RequestContext {
    std::array<std::uint8_t, 16> aes_key {};
    std::array<std::uint8_t, 16> request_hash {};
};

/// requested appPermissions (IEEE Std 1609.2 SequenceOfPsidSsp: ITS-AID and opaque SSP),
/// TS 102 941 V2.2.1 clause 6.2.3.2/6.2.3.3 request parameters
using Permissions = std::vector<std::pair<vanetza::ItsAid, ByteBuffer>>;

/// Clause 6.2.3.2.1 inputs
struct EnrolmentRequestParameters {
    ByteBuffer its_id;                    // canonical identifier (initial) or HashedId8 of the current EC (re-enrolment)
    KeyPair verification_key;             // new key pair; the private key signs the proof of possession
    Permissions app_permissions;          // requestedSubjectAttributes.appPermissions
    PrivateKey outer_signer_key;          // canonical private key (initial) or current EC private key
    const Certificate* current_ec = nullptr; // set for re-enrolment: outer signer = digest of the EC
    HashAlgorithm hash = HashAlgorithm::SHA256;
};

/** Build the EtsiTs103097Data-Encrypted EnrolmentRequest for the EA whose certificate
 * carries the encryption key. Result::invalid_argument for missing keys or an EA
 * certificate without encryptionKey, security_unavailable on backend failure. */
Result build_enrolment_request(vanetza::security::Backend&, EciesBackend&, vanetza::Clock::time_point now,
                               const EnrolmentRequestParameters&, const Certificate& ea, ByteBuffer& encoded,
                               RequestContext&);

/// Clause 6.2.3.2.2 InnerEcResponse
struct EnrolmentResponse {
    std::uint8_t response_code = 0; // EnrolmentResponseCode, 0 = ok
    std::optional<Certificate> certificate;
};

/** Decrypt with the request context (pskRecipInfo must match), verify the EA signature
 * (signer digest = HashedId8 of ea, psid 623), check the requestHash, decode. Result::rejected
 * when any check fails; the response is never trusted on decoding alone. */
Result parse_enrolment_response(vanetza::security::Backend&, EciesBackend&, const RequestContext&, const Certificate& ea,
                                const ByteBuffer& encoded, EnrolmentResponse&);

/// Clause 6.2.3.3.1 inputs
struct AuthorizationRequestParameters {
    KeyPair verification_key;                 // new AT key pair
    std::optional<KeyPair> encryption_key;    // optional AT encryption key
    Permissions app_permissions;              // shall be present
    std::optional<std::pair<vanetza::Clock::time_point, std::uint16_t>> validity_period; // start, hours
    const Certificate* ec = nullptr;          // enrolment credential signing SharedAtRequest
    PrivateKey ec_key;
    bool privacy = true;    // [Itss_WithPrivacy]: EC signature encrypted for the EA
    bool include_pop = true; // AuthorizationRequestMessageWithPop
    HashAlgorithm hash = HashAlgorithm::SHA256;
};

Result build_authorization_request(vanetza::security::Backend&, EciesBackend&, vanetza::Clock::time_point now,
                                   const AuthorizationRequestParameters&, const Certificate& ea, const Certificate& aa,
                                   ByteBuffer& encoded, RequestContext&);

/// Clause 6.2.3.3.2 InnerAtResponse
struct AuthorizationResponse {
    std::uint8_t response_code = 0; // AuthorizationResponseCode, 0 = ok
    std::optional<Certificate> certificate;
};

Result parse_authorization_response(vanetza::security::Backend&, EciesBackend&, const RequestContext&, const Certificate& aa,
                                    const ByteBuffer& encoded, AuthorizationResponse&);

// ---- Building blocks shared with tests and authority-side tooling ---------------------

/// EtsiTs103097Data-Signed over a payload: signer self (signer_cert null) or digest of signer_cert
std::optional<ByteBuffer> sign_data(vanetza::security::Backend&, vanetza::Clock::time_point now, HashAlgorithm,
                                    const ByteBuffer& payload, const PrivateKey& key, const Certificate* signer_cert);
/// EtsiTs103097Data-SignedExternalPayload: extDataHash = SHA-256 of external_payload
std::optional<ByteBuffer> sign_external(vanetza::security::Backend&, vanetza::Clock::time_point now,
                                        const ByteBuffer& external_payload, const PrivateKey& key,
                                        const Certificate& signer_cert);
/// EtsiTs103097Data-Encrypted for one certificate recipient; aes_key/nonce generated, key returned
std::optional<ByteBuffer> encrypt_for(vanetza::security::Backend&, EciesBackend&, const Certificate& recipient,
                                      const ByteBuffer& plaintext, std::array<std::uint8_t, 16>& aes_key);
/// EtsiTs103097Data-Encrypted with pskRecipInfo for a known symmetric key
std::optional<ByteBuffer> encrypt_with_psk(EciesBackend&, const std::array<std::uint8_t, 16>& aes_key, const ByteBuffer& plaintext);
/// Decrypt an EtsiTs103097Data-Encrypted addressed to a certificate (certRecipInfo) with its private encryption key
std::optional<ByteBuffer> decrypt_as_recipient(vanetza::security::Backend&, EciesBackend&, const Certificate& recipient,
                                               const PrivateKey& encryption_key, const ByteBuffer& encoded,
                                               std::array<std::uint8_t, 16>* aes_key = nullptr);
/// Decrypt an EtsiTs103097Data-Encrypted whose pskRecipInfo matches aes_key
std::optional<ByteBuffer> decrypt_with_psk(EciesBackend&, const std::array<std::uint8_t, 16>& aes_key, const ByteBuffer& encoded);
/// Verify an EtsiTs103097Data-Signed: self-signed with public_key, or by signer_cert when given; returns the payload
std::optional<ByteBuffer> verify_signed(vanetza::security::Backend&, const ByteBuffer& encoded, const PublicKey* self_key,
                                        const Certificate* signer_cert, vanetza::ItsAid expected_psid);

// ---- TS 102 941 V2.2.1 clause 6.3: trust list and revocation list of a root CA ----------
//
// RcaCertificateTrustListMessage (clause 6.3.2, 6.3.4, A.2.7): EtsiTs103097Data-Signed over an
// EtsiTs102941Data{certificateTrustListRca ToBeSignedRcaCtl}, signed with the RCA's key, the
// signer carrying the RCA certificate, psid = CTL service (TS 102 965 Table A.1, 624), the RCA
// certificate holding the CTL appPermissions (TS 102 941 Table B.3: 0138 for a root CTL).
// CertificateRevocationListMessage (clause 6.3.3): the same over
// EtsiTs102941Data{certificateRevocationList ToBeSignedCrl}, psid = CRL service (622).
// Clause 6.3.6: an ITS-S accepts either only when it verifies as signed by its RCA; it then
// takes the EA/AA entries as trusted issuers and the CRL entries as revoked.

using Time32 = std::uint32_t; // IEEE Std 1609.2 Time32, seconds since 2004-01-01 00:00:00 TAI

struct TrustListEntries {
    struct Authority { ByteBuffer certificate; std::string access_point; };   // EaEntry / AaEntry
    struct DistributionCentre { std::string url; std::vector<HashedId8> certificates; }; // DcEntry
    std::vector<Authority> ea, aa;
    std::vector<DistributionCentre> dc;
};

/// FullCtl (isFullCtl true, ctlCommands add only) of an RCA, version 1; ctl_sequence 0..255
std::optional<ByteBuffer> build_rca_ctl(vanetza::security::Backend&, vanetza::Clock::time_point now, const Certificate& rca,
                                        const PrivateKey& rca_key, const TrustListEntries&, Time32 next_update,
                                        std::uint8_t ctl_sequence);
/// CRL of an RCA, version 1
std::optional<ByteBuffer> build_crl(vanetza::security::Backend&, vanetza::Clock::time_point now, const Certificate& rca,
                                    const PrivateKey& rca_key, const std::vector<HashedId8>& revoked, Time32 this_update,
                                    Time32 next_update);

struct RcaTrustList {
    std::uint8_t sequence = 0;
    Time32 next_update = 0;
    bool full = true;
    std::vector<Certificate> ea, aa;                       // added entries (issuer of each: the RCA, checked)
    std::vector<TrustListEntries::DistributionCentre> dc;
    std::vector<HashedId8> deleted;                        // DeltaCtl delete commands (certificates)
    std::vector<std::string> deleted_dc;
};
/// Clause 6.3.6: the message verifies as signed by rca (signer certificate equal to rca,
/// psid 624, rca permitted for the CTL service), decodes as an RCA CTL of version 1 and every
/// EA/AA entry is issued by rca with a verifying signature (IEEE Std 1609.2 clause 5.3.1).
std::optional<RcaTrustList> parse_rca_ctl(vanetza::security::Backend&, const ByteBuffer& message, const Certificate& rca);

struct RevocationList {
    Time32 this_update = 0, next_update = 0;
    std::vector<HashedId8> revoked;
};
/// the same for a CRL (psid 622, rca permitted for the CRL service)
std::optional<RevocationList> parse_crl(vanetza::security::Backend&, const ByteBuffer& message, const Certificate& rca);

/// Clause 6.3.6: the EA/AA entries become trusted issuers (TrustConfiguration::add_authority);
/// returns the number added (entries already known are not counted)
std::size_t apply(const RcaTrustList&, vanetza_idf::security::TrustConfiguration&);
/// Clause 6.3.6: the CRL entries become revocations by the RCA (TrustConfiguration::revoke),
/// replacing the RCA's earlier list; returns the number of entries
std::size_t apply(const RevocationList&, const Certificate& rca, vanetza_idf::security::TrustConfiguration&);

} // namespace vanetza_idf::pki
