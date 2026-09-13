#include "test_trust_domain.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v3/asn1_types.hpp>
#include <chrono>
#include <string>

namespace vidf_test {
using namespace vanetza;
using namespace vanetza::security;
using vanetza::security::v3::Certificate;

namespace {
struct assign_compressed_point : boost::static_visitor<> {
    Vanetza_Security_EccP256CurvePoint* point;
    explicit assign_compressed_point(Vanetza_Security_EccP256CurvePoint* p) : point(p) {}
    void operator()(const Compressed_Lsb_Y_0& p) const {
        point->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
        OCTET_STRING_fromBuf(&point->choice.compressed_y_0, reinterpret_cast<const char*>(p.x.data()), p.x.size());
    }
    void operator()(const Compressed_Lsb_Y_1& p) const {
        point->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
        OCTET_STRING_fromBuf(&point->choice.compressed_y_1, reinterpret_cast<const char*>(p.x.data()), p.x.size());
    }
    template<class T> void operator()(const T&) const { point->present = Vanetza_Security_EccP256CurvePoint_PR_NOTHING; }
};

// TS 103 097 clause 6 common fields; canonical form: compressed verification key.
void common_fields(Certificate& cert, const PublicKey& verification, Clock::time_point start, unsigned hours,
                   Vanetza_Security_Duration_PR unit) {
    cert->version = 3;
    cert->type = Vanetza_Security_CertificateType_explicit;
    static const char craca[3] = {0, 0, 0};
    OCTET_STRING_fromBuf(&cert->toBeSigned.cracaId, craca, sizeof(craca));
    cert->toBeSigned.crlSeries = 0;
    cert->toBeSigned.validityPeriod.start = v2::convert_time32(start);
    cert->toBeSigned.validityPeriod.duration.present = unit;
    cert->toBeSigned.validityPeriod.duration.choice.hours = hours; // same storage for every unit
    ecdsa256::PublicKey legacy;
    std::copy(verification.x.begin(), verification.x.end(), legacy.x.begin());
    std::copy(verification.y.begin(), verification.y.end(), legacy.y.begin());
    auto& indicator = cert->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    indicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    assign_compressed_point visitor(&indicator.choice.verificationKey.choice.ecdsaNistP256);
    boost::apply_visitor(visitor, compress_public_key(legacy));
}

void issue_permissions(Certificate& ca) {
    // certIssuePermissions (clauses 7.2.3/7.2.4): explicit PSID/SSP ranges the CA may issue.
    auto* group = v3::asn1::allocate<v3::asn1::PsidGroupPermissions>();
    group->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    v3::add_psid_group_permission(group, aid::CA, {0x01, 0xff, 0xfc}, {0xff, 0x00, 0x03});
    v3::add_psid_group_permission(group, aid::DEN, {0x01, 0xff, 0xff, 0xff}, {0xff, 0x00, 0x00, 0x00});
    v3::add_psid_group_permission(group, aid::VRU, {0x01}, {0xff});
    v3::add_psid_group_permission(group, aid::GN_MGMT, {0x00}, {0xff});
    v3::add_psid_group_permission(group, aid::SCR, {0x01, 0xc0}, {0xff, 0x3f});
    ca.add_cert_issue_permission(group);
}

// Clause 7.2.4: a subordinate CA carries an encryption key for the ECIES of TS 102 941 and
// appPermissions to sign certificate responses (SCR).
void authority_fields(Certificate& ca, const std::string& name, const PublicKey& encryption) {
    ca->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&ca->toBeSigned.id.choice.name, name.data(), name.size());
    issue_permissions(ca);
    ca.add_app_permission(aid::SCR, {0x01, 0xc0});
    auto* key = v3::asn1::allocate<v3::asn1::PublicEncryptionKey>();
    key->supportedSymmAlg = Vanetza_Security_SymmAlgorithm_aes128Ccm;
    key->publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
    ecdsa256::PublicKey legacy;
    std::copy(encryption.x.begin(), encryption.x.end(), legacy.x.begin());
    std::copy(encryption.y.begin(), encryption.y.end(), legacy.y.begin());
    assign_compressed_point visitor(&key->publicKey.choice.eciesNistP256);
    boost::apply_visitor(visitor, compress_public_key(legacy));
    ca->toBeSigned.encryptionKey = key;
}

} // namespace

TrustDomain::KeyMaterial TrustDomain::fresh_key() const {
    const auto pair = backend_.generate_key_pair();
    KeyMaterial material;
    material.priv.type = KeyType::NistP256;
    material.priv.key.assign(pair.private_key.key.begin(), pair.private_key.key.end());
    material.pub.type = KeyType::NistP256;
    material.pub.compression = KeyCompression::NoCompression;
    material.pub.x.assign(pair.public_key.x.begin(), pair.public_key.x.end());
    material.pub.y.assign(pair.public_key.y.begin(), pair.public_key.y.end());
    return material;
}

void TrustDomain::sign(Certificate& subject, const Certificate* issuer, const PrivateKey& issuer_key) const {
    if (issuer) {
        subject->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
        const auto digest = issuer->calculate_digest();
        OCTET_STRING_fromBuf(&subject->issuer.choice.sha256AndDigest,
                             reinterpret_cast<const char*>(digest->data()), digest->size());
    } else {
        subject->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        subject->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
    }
    // IEEE 1609.2 clause 5.3.1: Hash(Hash(COER(toBeSigned)) || Hash(COER(issuer certificate) or ""))
    const ByteBuffer tbs = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedCertificate, &subject->toBeSigned);
    ByteBuffer input = backend_.calculate_hash(HashAlgorithm::SHA256, tbs);
    const ByteBuffer issuer_hash = backend_.calculate_hash(HashAlgorithm::SHA256, issuer ? issuer->encode() : ByteBuffer {});
    input.insert(input.end(), issuer_hash.begin(), issuer_hash.end());
    const auto signature = backend_.sign_digest(issuer_key, backend_.calculate_hash(HashAlgorithm::SHA256, input));
    EcdsaSignature ecdsa;
    ecdsa.R = X_Coordinate_Only {signature.r}; // canonical x-only r
    ecdsa.s = signature.s;
    subject.set_signature(ecdsa);
}

bool TrustDomain::verify_chain_signature(const Certificate& subject, const Certificate& issuer) const {
    const auto signature = v3::get_signature(*subject.content());
    const auto public_key = v3::get_public_key(*issuer.content());
    if (!signature || !public_key) return false;
    const ByteBuffer tbs = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedCertificate, &subject->toBeSigned);
    ByteBuffer input = backend_.calculate_hash(HashAlgorithm::SHA256, tbs);
    const ByteBuffer issuer_hash = backend_.calculate_hash(HashAlgorithm::SHA256,
        subject.issuer_is_self() ? ByteBuffer {} : issuer.encode());
    input.insert(input.end(), issuer_hash.begin(), issuer_hash.end());
    return backend_.verify_digest(*public_key, backend_.calculate_hash(HashAlgorithm::SHA256, input), *signature);
}

TrustDomain::TrustDomain(Backend& backend, Clock::time_point now) : backend_(backend) {
    const auto start = now - std::chrono::hours(1);
    // Root CA (clause 7.2.3): self-signed, name, issuing permissions.
    auto root_key = fresh_key();
    root.key = root_key.priv;
    common_fields(root.certificate, root_key.pub, start, 4, Vanetza_Security_Duration_PR_years);
    static const std::string root_name("vanetza-idf test root");
    root.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&root.certificate->toBeSigned.id.choice.name, root_name.data(), root_name.size());
    issue_permissions(root.certificate);
    sign(root.certificate, nullptr, root.key);
    // Authorization authority (clause 7.2.4): issued by the root, with an encryption key.
    auto aa_key = fresh_key();
    auto aa_enc = fresh_key();
    aa.key = aa_key.priv;
    aa_encryption_key = aa_enc.priv;
    common_fields(aa.certificate, aa_key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(aa.certificate, "vanetza-idf test AA", aa_enc.pub);
    sign(aa.certificate, &root.certificate, root.key);
    // Enrolment authority (clause 7.2.4): issued by the root, with an encryption key.
    auto ea_key = fresh_key();
    auto ea_enc = fresh_key();
    ea.key = ea_key.priv;
    ea_encryption_key = ea_enc.priv;
    common_fields(ea.certificate, ea_key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(ea.certificate, "vanetza-idf test EA", ea_enc.pub);
    sign(ea.certificate, &root.certificate, root.key);
}

Credential TrustDomain::issue_ticket(const Credential& authority, const Permissions& permissions,
                                     Clock::time_point start, unsigned hours) const {
    Credential ticket;
    auto ticket_key = fresh_key();
    ticket.key = ticket_key.priv;
    common_fields(ticket.certificate, ticket_key.pub, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    for (const auto& permission : permissions) ticket.certificate.add_app_permission(permission.first, permission.second);
    sign(ticket.certificate, &authority.certificate, authority.key);
    return ticket;
}

Credential TrustDomain::issue_authority(const std::string& name, Clock::time_point start) const {
    Credential authority;
    auto key = fresh_key();
    auto enc = fresh_key();
    authority.key = key.priv;
    common_fields(authority.certificate, key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(authority.certificate, name, enc.pub);
    sign(authority.certificate, &root.certificate, root.key);
    return authority;
}

Certificate TrustDomain::issue_ticket_for(const PublicKey& verification, const Permissions& permissions,
                                          Clock::time_point start, unsigned hours) const {
    Certificate ticket;
    common_fields(ticket, verification, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none; // clause 7.2.1
    for (const auto& permission : permissions) ticket.add_app_permission(permission.first, permission.second);
    sign(ticket, &aa.certificate, aa.key);
    return ticket;
}

Certificate TrustDomain::issue_credential_for(const PublicKey& verification, const std::string& name,
                                              Clock::time_point start, unsigned hours) const {
    Certificate credential;
    common_fields(credential, verification, start, hours, Vanetza_Security_Duration_PR_hours);
    credential->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name; // clause 7.2.2
    OCTET_STRING_fromBuf(&credential->toBeSigned.id.choice.name, name.data(), name.size());
    credential.add_app_permission(aid::SCR, {0x01, 0xc0});
    sign(credential, &ea.certificate, ea.key);
    return credential;
}

Credential TrustDomain::issue_ticket(const Permissions& permissions, Clock::time_point start, unsigned hours) const {
    Credential ticket;
    auto ticket_key = fresh_key();
    ticket.key = ticket_key.priv;
    common_fields(ticket.certificate, ticket_key.pub, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none; // clause 7.2.1
    for (const auto& permission : permissions) ticket.certificate.add_app_permission(permission.first, permission.second);
    sign(ticket.certificate, &aa.certificate, aa.key);
    return ticket;
}

} // namespace vidf_test
