#pragma once
// TS 102 941 V2.2.1 clause 6.2.3 EA/AA-side tooling: decrypt and verify inbound
// enrolment/authorization requests, and sign+encrypt the responses. This is the
// "authority-side tooling" vanetza_idf::pki's own doc comment (pki.hpp) leaves to the
// application; it is built from the same building blocks the ITS-S side already
// exposes as "shared with tests and authority-side tooling" (decrypt_as_recipient,
// verify_signed, sign_data, encrypt_with_psk) plus the parsing test_pki.cpp already
// proved correct in-process. Used both by the regression tests and by vidf_issue's
// ea-respond/aa-respond commands; a lab/test authority, not a production PKI: no
// replay protection, no butterfly keys (clause 6.2.3.5), no CA-side revocation checks.
#include "test_trust_domain.hpp"
#include <vanetza_idf/pki.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <array>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace vidf_test {

using vanetza::ByteBuffer;

/// Answers an EnrolmentRequest/AuthorizationRequest (clause 6.2.3.2.2/6.2.3.3.2): signs
/// EtsiTs102941Data{...Response} with `signer` and encrypts it with the request's own
/// AES key (pskRecipInfo), the requestHash set to the leftmost 16 octets of SHA-256 of
/// the (still encrypted) request, as clause 6.2.3.2.2/6.2.3.3.2 require.
struct Authority {
    vanetza::security::Backend& backend;
    vanetza_idf::pki::EciesBackend& ecies;

    ByteBuffer enrolment_response(vanetza::Clock::time_point now, const std::array<std::uint8_t, 16>& aes_key,
                                  const ByteBuffer& request, std::uint8_t response_code,
                                  const vanetza::security::v3::Certificate* ec, const Credential& signer) const;
    ByteBuffer authorization_response(vanetza::Clock::time_point now, const std::array<std::uint8_t, 16>& aes_key,
                                      const ByteBuffer& request, std::uint8_t response_code,
                                      const vanetza::security::v3::Certificate* at, const Credential& signer) const;
};

/// Clause 6.2.3.2.1 InnerEcRequest, decrypted and verified from the wire.
struct ParsedEnrolmentRequest {
    ByteBuffer its_id;                                    // canonical identifier or HashedId8 of the current EC
    vanetza::security::PublicKey verification_key;        // the new key the request asks to be certified
    vanetza_idf::pki::Permissions app_permissions;
    bool re_enrolment = false;                            // its_id names the current EC (outer signer = its digest)
};

/** EA decrypts `encoded` with its own certificate/encryption key, then verifies the outer
 * signature: self-signed with *canonical_key (initial enrolment) or by the digest of
 * *current_ec (re-enrolment) — exactly one of the two must be given, matching how
 * build_enrolment_request itself lets the caller choose. The inner proof of possession is
 * verified against the verification key carried inside the request itself (self-consistent:
 * a forged key cannot both appear in the payload and produce a valid signature over it
 * without the matching private key). std::nullopt on any decrypt/signature/PoP/decode
 * failure -- nothing is accepted on decoding alone. */
std::optional<ParsedEnrolmentRequest> parse_enrolment_request(vanetza::security::Backend&, vanetza_idf::pki::EciesBackend&,
                                                               const Credential& ea,
                                                               const vanetza::security::PrivateKey& ea_encryption_key,
                                                               const ByteBuffer& encoded, const vanetza::security::PublicKey* canonical_key,
                                                               const vanetza::security::v3::Certificate* current_ec,
                                                               std::array<std::uint8_t, 16>& aes_key_out);

/// Clause 6.2.3.3.1 InnerAtRequest/SharedAtRequest, decrypted and verified from the wire.
struct ParsedAuthorizationRequest {
    vanetza::security::PublicKey verification_key;        // the new AT key the request asks to be certified
    vanetza_idf::pki::Permissions app_permissions;
    vanetza::security::HashedId8 ea_id {};                // SharedAtRequest.eaId: which EA to validate entitlement with
    ByteBuffer shared_at_request;                         // OER SharedAtRequest, for validate_entitlement's hash check
    bool ec_signature_encrypted = false;                  // privacy: the EC signature is encrypted for the EA
    ByteBuffer ec_signature;                               // EtsiTs103097Data, encrypted (for the EA) or in clear
};

/** AA decrypts `encoded` with its own certificate/encryption key, verifies the proof of
 * possession (self-signed with the requested AT key, bootstrapped from the payload the
 * same way as parse_enrolment_request), and decodes InnerAtRequest/SharedAtRequest.
 * The "no proof of possession" variant (AuthorizationRequestMessage, unsecured envelope)
 * is accepted too, per clause 6.2.3.3.1. std::nullopt on any failure. */
std::optional<ParsedAuthorizationRequest> parse_authorization_request(vanetza::security::Backend&, vanetza_idf::pki::EciesBackend&,
                                                                       const Credential& aa,
                                                                       const vanetza::security::PrivateKey& aa_encryption_key,
                                                                       const ByteBuffer& encoded,
                                                                       std::array<std::uint8_t, 16>& aes_key_out);

/** The "AA <-> EA: validate entitlement" step: the EA decrypts (if privacy was used) the
 * EC signature forwarded inside the authorization request and checks it verifies against
 * candidate_ec and hashes to req.shared_at_request (TS 102 941 clause 6.2.3.3.1: the EC
 * signs the SharedAtRequest as a SignedExternalPayload). True only when candidate_ec is
 * the EC that actually signed this exact request. */
bool validate_entitlement(vanetza::security::Backend&, vanetza_idf::pki::EciesBackend&, const Credential& ea,
                          const vanetza::security::PrivateKey& ea_encryption_key, const ParsedAuthorizationRequest&,
                          const vanetza::security::v3::Certificate& candidate_ec);

} // namespace vidf_test
