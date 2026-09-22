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

// PsidSspRange without sspRange: the CA may issue any SSP for that PSID (IEEE Std 1609.2
// 6.4.29 SspRange: omitting it means "all", the only range consistent with a ticket
// whose ssp is omitted, as GN-MGMT tickets are).
void add_psid_all_permission(v3::asn1::PsidGroupPermissions* group, ItsAid aid) {
    auto* range = vanetza::asn1::allocate<v3::asn1::PsidSspRange>();
    range->psid = aid;
    ASN_SEQUENCE_ADD(&group->subjectPermissions.choice.Explicit, range);
}

// certIssuePermissions (clauses 7.2.3/7.2.4) shaped like the EU CCMS CPOC Protocol
// Release 3.0 root profile: explicit PSID/SSP ranges the CA may issue, the SSP ranges
// with the IEEE Std 1609.2 6.4.30 bitmask rule (a 1 bit fixes the subordinate's bit).
//  * The application group (CA, DEN, VRU, GN-MGMT and the end-entity part of the
//    Secured Certificate Request service, TS 102 941 V2.2.1 Table B.6: EC signs
//    enrolment and authorization requests, 01C0/FF3F). In a root this group carries
//    minChainLength 2 (IEEE Std 1609.2 6.4.28: the chain below the root runs through
//    the AA/EA down to the ticket/credential, so its length is 2) and eeType app+enrol;
//    a subordinate CA keeps the defaults (1, app) because it issues end entities only.
//  * In a root, a second group for the CA side of the Secured Certificate Request
//    service (013E/FFC1: the SSP bits an EA/AA may hold to sign responses, Table B.6),
//    chain length 1 as in the CPOC profile.
void issue_permissions(Certificate& ca, bool root) {
    auto* group = v3::asn1::allocate<v3::asn1::PsidGroupPermissions>();
    group->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    v3::add_psid_group_permission(group, aid::CA, {0x01, 0xff, 0xfc}, {0xff, 0x00, 0x03});
    v3::add_psid_group_permission(group, aid::DEN, {0x01, 0xff, 0xff, 0xff}, {0xff, 0x00, 0x00, 0x00});
    v3::add_psid_group_permission(group, aid::VRU, {0x01}, {0xff});
    add_psid_all_permission(group, aid::GN_MGMT);
    v3::add_psid_group_permission(group, aid::SCR, {0x01, 0xc0}, {0xff, 0x3f});
    if (root) {
        group->minChainLength = vanetza::asn1::allocate<long>();
        *group->minChainLength = 2;
        group->eeType = vanetza::asn1::allocate<Vanetza_Security_EndEntityType_t>();
        // EndEntityType BIT STRING (SIZE (8)) with app(0) and enrol(1) set; the pinned asn1c
        // schema defaults an absent eeType to 00H, IEEE Std 1609.2-2022 to {app}: encode it.
        group->eeType->buf = static_cast<std::uint8_t*>(vanetza::asn1::allocate(1));
        group->eeType->buf[0] = 0xc0;
        group->eeType->size = 1;
        group->eeType->bits_unused = 0;
    }
    ca.add_cert_issue_permission(group);
    if (root) {
        auto* authorities = v3::asn1::allocate<v3::asn1::PsidGroupPermissions>();
        authorities->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
        v3::add_psid_group_permission(authorities, aid::SCR, {0x01, 0x3e}, {0xff, 0xc1});
        ca.add_cert_issue_permission(authorities);
    }
}

// Clause 7.2.3: the root's appPermissions are the CRL and CTL services (TS 102 941 V2.2.1
// Table B.3: a root CTL lists EA, AA and DC entries, SSP 0138; clause B.3: CRL SSP 01).
void root_fields(Certificate& root, const std::string& name) {
    root->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&root->toBeSigned.id.choice.name, name.data(), name.size());
    root.add_app_permission(aid::CRL, {0x01});
    root.add_app_permission(aid::CTL, {0x01, 0x38});
    issue_permissions(root, true);
}

// Clause 7.2.4: a subordinate CA carries an encryption key for the ECIES of TS 102 941 and
// appPermissions to sign certificate responses (SCR): an AA signs authorization validation
// requests and authorization responses (TS 102 941 V2.2.1 Table B.6, bits 2 and 3: 0130), an
// EA signs authorization validation responses, enrolment responses and CA certificate
// requests (bits 4 to 6: 010E).
enum class AuthorityKind { aa, ea };
void authority_fields(Certificate& ca, const std::string& name, const PublicKey& encryption, AuthorityKind kind) {
    ca->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&ca->toBeSigned.id.choice.name, name.data(), name.size());
    issue_permissions(ca, false);
    ca.add_app_permission(aid::SCR, kind == AuthorityKind::aa ? ByteBuffer {0x01, 0x30} : ByteBuffer {0x01, 0x0e});
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
    root_fields(root.certificate, "vanetza-idf test root");
    sign(root.certificate, nullptr, root.key);
    // Authorization authority (clause 7.2.4): issued by the root, with an encryption key.
    auto aa_key = fresh_key();
    auto aa_enc = fresh_key();
    aa.key = aa_key.priv;
    aa_encryption_key = aa_enc.priv;
    common_fields(aa.certificate, aa_key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(aa.certificate, "vanetza-idf test AA", aa_enc.pub, AuthorityKind::aa);
    sign(aa.certificate, &root.certificate, root.key);
    // Enrolment authority (clause 7.2.4): issued by the root, with an encryption key.
    auto ea_key = fresh_key();
    auto ea_enc = fresh_key();
    ea.key = ea_key.priv;
    ea_encryption_key = ea_enc.priv;
    common_fields(ea.certificate, ea_key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(ea.certificate, "vanetza-idf test EA", ea_enc.pub, AuthorityKind::ea);
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

Credential TrustDomain::issue_ticket(const Credential& authority, const Permissions& permissions,
                                     Clock::time_point start, unsigned hours, const CircularRegion& region) const {
    Credential ticket;
    auto ticket_key = fresh_key();
    ticket.key = ticket_key.priv;
    common_fields(ticket.certificate, ticket_key.pub, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    for (const auto& permission : permissions) ticket.certificate.add_app_permission(permission.first, permission.second);
    auto* geographic = vanetza::asn1::allocate<Vanetza_Security_GeographicRegion_t>();
    geographic->present = Vanetza_Security_GeographicRegion_PR_circularRegion;
    geographic->choice.circularRegion.center.latitude = region.latitude;
    geographic->choice.circularRegion.center.longitude = region.longitude;
    geographic->choice.circularRegion.radius = region.radius_m;
    ticket.certificate->toBeSigned.region = geographic;
    sign(ticket.certificate, &authority.certificate, authority.key);
    return ticket;
}

Credential TrustDomain::issue_authority(const std::string& name, Clock::time_point start) const {
    Credential authority;
    auto key = fresh_key();
    auto enc = fresh_key();
    authority.key = key.priv;
    common_fields(authority.certificate, key.pub, start, 3, Vanetza_Security_Duration_PR_years);
    authority_fields(authority.certificate, name, enc.pub, AuthorityKind::aa);
    sign(authority.certificate, &root.certificate, root.key);
    return authority;
}

// A subordinate CA may issue what its issuer allows through it: every group of the issuer
// whose chain-length window reaches two certificates down (IEEE Std 1609.2 6.4.28) and
// whose eeType admits authorization certificates is copied as a group with the defaults
// (chain length 1, app); the issuer's region, if any, is inherited (6.4.17: no part of
// the subordinate's region may lie outside the issuer's; the same region is within).
void derive_from_issuer(Certificate& ca, const Certificate& issuer) {
    if (const auto* groups = issuer->toBeSigned.certIssuePermissions) {
        for (int i = 0; i < groups->list.count; ++i) {
            const auto* group = groups->list.array[i];
            if (!group) continue;
            const long min = group->minChainLength ? *group->minChainLength : 1;
            const long range = group->chainLengthRange;
            const bool reaches = min <= 2 && (range < 0 || min + range >= 2);
            const bool app = !group->eeType || group->eeType->size == 0 || (group->eeType->buf[0] & 0x80);
            if (!reaches || !app) continue;
            auto* derived = v3::asn1::allocate<v3::asn1::PsidGroupPermissions>();
            if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all) {
                derived->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_all;
            } else if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_explicit) {
                derived->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
                const auto& ranges = group->subjectPermissions.choice.Explicit.list;
                for (int k = 0; k < ranges.count; ++k) {
                    if (!ranges.array[k]) continue;
                    auto* range = static_cast<v3::asn1::PsidSspRange*>(vanetza::asn1::copy(asn_DEF_Vanetza_Security_PsidSspRange, ranges.array[k]));
                    ASN_SEQUENCE_ADD(&derived->subjectPermissions.choice.Explicit, range);
                }
            } else {
                vanetza::asn1::free(asn_DEF_Vanetza_Security_PsidGroupPermissions, derived);
                continue;
            }
            ca.add_cert_issue_permission(derived);
        }
    }
    if (const auto* region = issuer->toBeSigned.region) {
        ca->toBeSigned.region = static_cast<Vanetza_Security_GeographicRegion_t*>(vanetza::asn1::copy(asn_DEF_Vanetza_Security_GeographicRegion, region));
    }
}

Credential TrustDomain::issue_authority(const Credential& issuer, const std::string& name, Clock::time_point start,
                                        unsigned years, PrivateKey* encryption_key) const {
    Credential authority;
    auto key = fresh_key();
    auto enc = fresh_key();
    authority.key = key.priv;
    if (encryption_key) *encryption_key = enc.priv;
    common_fields(authority.certificate, key.pub, start, years, Vanetza_Security_Duration_PR_years);
    // clause 7.2.4 fields as for the lab AA, but the issuing permissions and the region come
    // from the issuer rather than from the lab profile
    authority.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&authority.certificate->toBeSigned.id.choice.name, name.data(), name.size());
    derive_from_issuer(authority.certificate, issuer.certificate);
    authority.certificate.add_app_permission(aid::SCR, {0x01, 0x30});
    auto* enc_key = v3::asn1::allocate<v3::asn1::PublicEncryptionKey>();
    enc_key->supportedSymmAlg = Vanetza_Security_SymmAlgorithm_aes128Ccm;
    enc_key->publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
    ecdsa256::PublicKey legacy;
    std::copy(enc.pub.x.begin(), enc.pub.x.end(), legacy.x.begin());
    std::copy(enc.pub.y.begin(), enc.pub.y.end(), legacy.y.begin());
    assign_compressed_point visitor(&enc_key->publicKey.choice.eciesNistP256);
    boost::apply_visitor(visitor, compress_public_key(legacy));
    authority.certificate->toBeSigned.encryptionKey = enc_key;
    sign(authority.certificate, &issuer.certificate, issuer.key);
    return authority;
}

Credential TrustDomain::issue_ticket(const Credential& authority, const Permissions& permissions, Clock::time_point start,
                                     unsigned hours, const Vanetza_Security_GeographicRegion_t* region) const {
    Credential ticket;
    auto ticket_key = fresh_key();
    ticket.key = ticket_key.priv;
    common_fields(ticket.certificate, ticket_key.pub, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket.certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    for (const auto& permission : permissions) ticket.certificate.add_app_permission(permission.first, permission.second);
    if (region) ticket.certificate->toBeSigned.region = static_cast<Vanetza_Security_GeographicRegion_t*>(vanetza::asn1::copy(asn_DEF_Vanetza_Security_GeographicRegion, region));
    sign(ticket.certificate, &authority.certificate, authority.key);
    return ticket;
}

Certificate TrustDomain::issue_root(const PrivateKey& key, const PublicKey& verification, const std::string& name,
                                    Clock::time_point start, unsigned years) const {
    Certificate certificate;
    common_fields(certificate, verification, start, years, Vanetza_Security_Duration_PR_years);
    root_fields(certificate, name);
    sign(certificate, nullptr, key);
    return certificate;
}

Certificate TrustDomain::issue_root_like(const PrivateKey& key, const PublicKey& verification, const std::string& name,
                                         Clock::time_point start, unsigned years, const Certificate& profile) const {
    Certificate certificate;
    common_fields(certificate, verification, start, years, Vanetza_Security_Duration_PR_years);
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&certificate->toBeSigned.id.choice.name, name.data(), name.size());
    // the profile's permissions and region, deep-copied; key, name and validity are ours
    if (profile->toBeSigned.appPermissions)
        certificate->toBeSigned.appPermissions = static_cast<v3::asn1::SequenceOfPsidSsp*>(
            vanetza::asn1::copy(asn_DEF_Vanetza_Security_SequenceOfPsidSsp, profile->toBeSigned.appPermissions));
    if (profile->toBeSigned.certIssuePermissions)
        certificate->toBeSigned.certIssuePermissions = static_cast<v3::asn1::SequenceOfPsidGroupPermissions*>(
            vanetza::asn1::copy(asn_DEF_Vanetza_Security_SequenceOfPsidGroupPermissions, profile->toBeSigned.certIssuePermissions));
    if (profile->toBeSigned.region)
        certificate->toBeSigned.region = static_cast<Vanetza_Security_GeographicRegion_t*>(
            vanetza::asn1::copy(asn_DEF_Vanetza_Security_GeographicRegion, profile->toBeSigned.region));
    sign(certificate, nullptr, key);
    return certificate;
}

Certificate TrustDomain::issue_ticket_for(const PublicKey& verification, const Permissions& permissions,
                                          Clock::time_point start, unsigned hours) const {
    return issue_ticket_for(aa, verification, permissions, start, hours);
}

Certificate TrustDomain::issue_ticket_for(const Credential& authority, const PublicKey& verification, const Permissions& permissions,
                                          Clock::time_point start, unsigned hours) const {
    Certificate ticket;
    common_fields(ticket, verification, start, hours, Vanetza_Security_Duration_PR_hours);
    ticket->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none; // clause 7.2.1
    for (const auto& permission : permissions) ticket.add_app_permission(permission.first, permission.second);
    sign(ticket, &authority.certificate, authority.key);
    return ticket;
}

Certificate TrustDomain::issue_credential_for(const PublicKey& verification, const std::string& name,
                                              Clock::time_point start, unsigned hours) const {
    return issue_credential_for(ea, verification, name, start, hours);
}

Certificate TrustDomain::issue_credential_for(const Credential& ea_issuer, const PublicKey& verification, const std::string& name,
                                              Clock::time_point start, unsigned hours) const {
    Certificate credential;
    common_fields(credential, verification, start, hours, Vanetza_Security_Duration_PR_hours);
    credential->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name; // clause 7.2.2
    OCTET_STRING_fromBuf(&credential->toBeSigned.id.choice.name, name.data(), name.size());
    credential.add_app_permission(aid::SCR, {0x01, 0xc0});
    sign(credential, &ea_issuer.certificate, ea_issuer.key);
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
