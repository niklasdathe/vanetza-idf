#include <vanetza_idf/security.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/security/encap_service.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#if VIDF_SECURITY_VERIFY
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <unordered_set>
#include <vector>
#endif
#include <algorithm>
#include <stdexcept>

namespace vanetza_idf::security {
using namespace vanetza;
using namespace vanetza::security;
namespace {
// TS 103 097 V2.2.1 clause 7.2.1: issuer is a digest, appPermissions present,
// certIssuePermissions absent, CertificateId none.
bool is_authorization_ticket(const Certificate& cert) {
    const auto& issuer = cert->issuer;
    const bool digest_issuer = issuer.present == Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest ||
                               issuer.present == Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest;
    return digest_issuer && cert.is_at_certificate() &&
           cert->toBeSigned.id.present == Vanetza_Security_CertificateId_PR_none;
}
} // namespace

// ---- CertificatePool --------------------------------------------------------

CertificatePool::CertificatePool(Backend& backend) : backend_(backend) {}

Result CertificatePool::add(const ByteBuffer& coer, const PrivateKey& key) {
    Certificate certificate;
    if (coer.empty() || !certificate.decode(coer) || !certificate.validate()) return Result::invalid_argument;
    return add(std::move(certificate), key);
}

Result CertificatePool::add(Certificate certificate, PrivateKey key) {
    if (!is_authorization_ticket(certificate)) return Result::invalid_argument;
    const auto type = certificate.get_verification_key_type();
    if (type == KeyType::Unspecified || key.type != type || key.key.size() != key_length(type))
        return Result::invalid_argument;
    const auto digest = certificate.calculate_digest();
    const auto public_key = v3::get_public_key(*certificate.content());
    if (!digest || !public_key) return Result::invalid_argument;
    for (const auto& ticket : tickets_) if (ticket.digest == *digest) return Result::invalid_argument;
    // The key must belong to this certificate: sign a digest and verify it with the
    // certificate's verification key. A provisioning mix-up fails here, not on air.
    try {
        const ByteBuffer probe = backend_.calculate_hash(v3::specified_hash_algorithm(type), certificate.encode());
        const auto signature = backend_.sign_digest(key, probe);
        if (!backend_.verify_digest(*public_key, probe, signature)) return Result::invalid_argument;
    } catch (const std::exception&) {
        return Result::invalid_argument;
    }
    tickets_.push_back(Ticket {std::move(certificate), std::move(key), *digest});
    return Result::accepted;
}

const CertificatePool::Ticket* CertificatePool::current() const {
    return tickets_.empty() ? nullptr : &tickets_[current_];
}

const CertificatePool::Ticket* CertificatePool::next_valid(Clock::time_point now) const {
    if (tickets_.size() < 2) return nullptr;
    for (std::size_t step = 1; step < tickets_.size(); ++step) {
        const auto& candidate = tickets_[(current_ + step) % tickets_.size()];
        if (candidate.certificate.valid_at_timepoint(now)) return &candidate;
    }
    return nullptr;
}

Result CertificatePool::select(const HashedId8& digest) {
    for (std::size_t i = 0; i < tickets_.size(); ++i) {
        if (tickets_[i].digest == digest) { current_ = i; return Result::accepted; }
    }
    return Result::invalid_argument;
}

std::size_t CertificatePool::prune(Clock::time_point now) {
    const auto time32 = v2::convert_time32(now);
    std::size_t removed = 0;
    for (std::size_t i = 0; i < tickets_.size();) {
        if (i != current_ && tickets_[i].certificate.get_start_and_end_validity().end_validity < time32) {
            tickets_.erase(tickets_.begin() + i);
            if (i < current_) --current_;
            ++removed;
        } else {
            ++i;
        }
    }
    return removed;
}

const Certificate& CertificatePool::own_certificate() {
    if (tickets_.empty()) throw std::logic_error("certificate pool is empty");
    return tickets_[current_].certificate;
}

const PrivateKey& CertificatePool::own_private_key() {
    if (tickets_.empty()) throw std::logic_error("certificate pool is empty");
    return tickets_[current_].key;
}

// ---- TrustConfiguration -----------------------------------------------------

Result TrustConfiguration::add_root(const ByteBuffer& coer) {
    Certificate certificate;
    if (coer.empty() || !certificate.decode(coer) || !certificate.validate()) return Result::invalid_argument;
    return add_root(certificate);
}

Result TrustConfiguration::add_root(const Certificate& certificate) {
    // TS 103 097 clause 7.2.3: self-signed with certIssuePermissions.
    if (!certificate.issuer_is_self() || !certificate.is_ca_certificate()) return Result::invalid_argument;
    if (!certificate.calculate_digest()) return Result::invalid_argument;
    roots_.insert(certificate);
    if (!issuers_.insert(certificate)) return Result::invalid_argument;
    authorities_.push_back(certificate);
    return Result::accepted;
}

Result TrustConfiguration::add_authority(const ByteBuffer& coer) {
    Certificate certificate;
    if (coer.empty() || !certificate.decode(coer) || !certificate.validate()) return Result::invalid_argument;
    return add_authority(certificate);
}

Result TrustConfiguration::add_authority(const Certificate& certificate) {
    // TS 103 097 clause 7.2.4: issued by digest, carries certIssuePermissions.
    if (certificate.issuer_is_self() || !certificate.is_ca_certificate()) return Result::invalid_argument;
    if (!issuers_.insert(certificate)) return Result::invalid_argument;
    authorities_.push_back(certificate);
    return Result::accepted;
}

// ---- Certificate signatures and message profiles ----------------------------

namespace {
bool verify_certificate_signature(Backend& backend, const Vanetza_Security_EtsiTs103097Certificate_t& subject,
                                  const Certificate* issuer) {
    const auto signature = v3::get_signature(subject);
    if (!signature) return false;
    HashAlgorithm hash = HashAlgorithm::SHA256;
    switch (subject.issuer.present) {
        case Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest:
            if (!issuer) return false;
            break;
        case Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest:
            if (!issuer) return false;
            hash = HashAlgorithm::SHA384;
            break;
        case Vanetza_Security_IssuerIdentifier_PR_self:
            hash = subject.issuer.choice.self == Vanetza_Security_HashAlgorithm_sha384 ? HashAlgorithm::SHA384 : HashAlgorithm::SHA256;
            issuer = nullptr; // IEEE Std 1609.2 clause 5.3.1: the empty string stands in for the issuer
            break;
        default:
            return false;
    }
    const auto public_key = v3::get_public_key(issuer ? *issuer->content() : subject);
    if (!public_key) return false;
    const ByteBuffer tbs = vanetza::asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedCertificate, &subject.toBeSigned);
    ByteBuffer input = backend.calculate_hash(hash, tbs);
    const ByteBuffer issuer_hash = backend.calculate_hash(hash, issuer ? issuer->encode() : ByteBuffer {});
    input.insert(input.end(), issuer_hash.begin(), issuer_hash.end());
    return backend.verify_digest(*public_key, backend.calculate_hash(hash, input), *signature);
}
} // namespace

bool verify_certificate_signature(Backend& backend, const Certificate& subject, const Certificate* issuer) {
    return subject.content() && verify_certificate_signature(backend, *subject.content(), issuer);
}

VerificationReport check_profile(const v3::SecuredMessage& msg) {
    if (msg.protocol_version() != 3) return VerificationReport::Incompatible_Protocol;
    if (!msg.is_signed()) return VerificationReport::Unsigned_Message;
    const auto* signed_data = msg->content->choice.signedData;
    if (!signed_data || !signed_data->tbsData) return VerificationReport::Incompatible_Protocol;
    const auto& tbs = *signed_data->tbsData;
    const auto& header = tbs.headerInfo;
    // clause 5.2: payload is an Ieee1609Dot2Data (protocolVersion 3) or an external hash
    if (!tbs.payload) return VerificationReport::Incompatible_Protocol;
    if (tbs.payload->data && tbs.payload->data->protocolVersion != 3) return VerificationReport::Incompatible_Protocol;
    if (!tbs.payload->data && !tbs.payload->extDataHash) return VerificationReport::Incompatible_Protocol;
    // clause 5.2 with IEEE Std 1609.2 clause 5.3.3: hashId follows the signing algorithm
    const bool sha384 = signed_data->hashId == Vanetza_Security_HashAlgorithm_sha384;
    switch (signed_data->signature.present) {
        case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
            if (sha384) return VerificationReport::Incompatible_Protocol;
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            if (!sha384) return VerificationReport::Incompatible_Protocol;
            break;
        default:
            return VerificationReport::Incompatible_Protocol;
    }
    if (!header.generationTime) return VerificationReport::Invalid_Timestamp; // "always present"
    if (header.p2pcdLearningRequest || header.missingCrlIdentifier) return VerificationReport::Incompatible_Protocol;
    switch (signed_data->signer.present) {
        case Vanetza_Security_SignerIdentifier_PR_digest:
        case Vanetza_Security_SignerIdentifier_PR_certificate:
            break;
        default:
            return VerificationReport::Unsupported_Signer_Identifier_Type;
    }
    const ItsAid its_aid = msg.its_aid();
    if (its_aid == aid::CA) {
        // clause 7.1.1: besides generationTime only inlineP2pcdRequest and requestedCertificate may appear
        if (header.expiryTime || header.generationLocation || header.encryptionKey) return VerificationReport::Incompatible_Protocol;
    } else if (its_aid == aid::DEN) {
        // clause 7.1.2: generationLocation present, signer certificate, nothing else
        if (!header.generationLocation || header.expiryTime || header.encryptionKey) return VerificationReport::Incompatible_Protocol;
        if (signed_data->signer.present != Vanetza_Security_SignerIdentifier_PR_certificate) return VerificationReport::Incompatible_Protocol;
    }
    return VerificationReport::Success;
}

namespace {
// IEEE Std 1609.2-2025 permission consistency along the chain, which the upstream
// validator reduces to "the issuer lists the ITS-AID". TS 103 097 V2.2.1 clause 5.2
// verifies an SPDU as IEEE Std 1609.2 clause 5.2 requires, and that includes the
// certificate chain consistency of clause 5.1.2:
//  * PsidGroupPermissions (6.4.28): minChainLength/chainLengthRange bound the length of
//    the chain from that certificate down to and including the end entity (-1: no upper
//    bound; 0 is invalid in certIssuePermissions); eeType must permit an authorization
//    certificate (app), absent eeType defaulting to {app}.
//  * SubjectPermissions (6.4.29): "all" covers every PSID not indicated explicitly by
//    another group of the same certificate; "explicit" lists PsidSspRange values.
//  * SspRange consistency (6.4.29/6.4.30): an omitted ssp needs a range "all" (or an
//    empty opaque entry); an opaque ssp must duplicate one opaque entry; a bitmapSsp
//    must equal sspValue in every bit position where sspBitmask is 1 and may not be
//    shorter than the last 1 bit of the mask nor longer than the mask.
//  * A subordinate CA's own PsidSspRange must nest inside its issuer's (6.4.30): the
//    issuer's range is "all", or for every 1 bit of the issuer's mask the subordinate's
//    mask bit is 1 and its value bit equals the issuer's; opaque entries must duplicate
//    the issuer's; "all" needs "all".
// Unknown CHOICE alternatives are critical information (5.2.6): fail closed.
namespace consistency {
using Group = Vanetza_Security_PsidGroupPermissions_t;
using Groups = Vanetza_Security_SequenceOfPsidGroupPermissions_t;
using Range = Vanetza_Security_PsidSspRange_t;
using Ssp = Vanetza_Security_ServiceSpecificPermissions_t;

bool octets_equal(const OCTET_STRING_t& a, const OCTET_STRING_t& b) {
    return a.size == b.size && (a.size == 0 || std::equal(a.buf, a.buf + a.size, b.buf));
}

bool ee_type_app(const Group& group) {
    if (!group.eeType || group.eeType->size == 0) return true; // DEFAULT {app}
    return (group.eeType->buf[0] & 0x80) != 0;                 // bit 0: app
}

bool chain_length_permits(const Group& group, unsigned depth) {
    const long min = group.minChainLength ? *group.minChainLength : 1;
    const long range = group.chainLengthRange;
    if (min < 1 || depth < static_cast<unsigned long>(min)) return false;
    return range < 0 || depth <= static_cast<unsigned long>(min + range);
}

const Range* find_range(const Group& group, long psid) {
    if (group.subjectPermissions.present != Vanetza_Security_SubjectPermissions_PR_explicit) return nullptr;
    const auto& list = group.subjectPermissions.choice.Explicit.list;
    for (int i = 0; i < list.count; ++i) {
        if (list.array[i] && list.array[i]->psid == psid) return list.array[i];
    }
    return nullptr;
}

bool listed_explicitly(const Groups& groups, long psid) {
    for (int i = 0; i < groups.list.count; ++i) {
        if (groups.list.array[i] && find_range(*groups.list.array[i], psid)) return true;
    }
    return false;
}

// end-entity ssp (nullptr: omitted) within a PsidSspRange's sspRange (nullptr: all)
bool ssp_within(const Ssp* ssp, const Vanetza_Security_SspRange_t* range) {
    if (!range || range->present == Vanetza_Security_SspRange_PR_all) return true;
    if (range->present == Vanetza_Security_SspRange_PR_opaque) {
        const auto& entries = range->choice.opaque.list;
        for (int i = 0; i < entries.count; ++i) {
            const OCTET_STRING_t* entry = entries.array[i];
            if (!entry) continue;
            if (!ssp) { if (entry->size == 0) return true; }
            else if (ssp->present == Vanetza_Security_ServiceSpecificPermissions_PR_opaque &&
                     octets_equal(*entry, ssp->choice.opaque)) return true;
        }
        return false;
    }
    if (range->present == Vanetza_Security_SspRange_PR_bitmapSspRange) {
        if (!ssp || ssp->present != Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp) return false;
        const OCTET_STRING_t& value = range->choice.bitmapSspRange.sspValue;
        const OCTET_STRING_t& mask = range->choice.bitmapSspRange.sspBitmask;
        const OCTET_STRING_t& bits = ssp->choice.bitmapSsp;
        if (value.size != mask.size || bits.size > mask.size) return false;
        for (std::size_t i = 0; i < mask.size; ++i) {
            if (i >= bits.size) { if (mask.buf[i]) return false; continue; }
            if ((bits.buf[i] & mask.buf[i]) != (value.buf[i] & mask.buf[i])) return false;
        }
        return true;
    }
    return false;
}

// an ancestor's certIssuePermissions cover one appPermissions entry of the end entity at
// the given chain length
bool covers(const Groups& groups, const Vanetza_Security_PsidSsp_t& entry, unsigned depth) {
    const bool elsewhere = listed_explicitly(groups, entry.psid);
    for (int i = 0; i < groups.list.count; ++i) {
        const Group* group = groups.list.array[i];
        if (!group || !ee_type_app(*group) || !chain_length_permits(*group, depth)) continue;
        if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all) {
            if (!elsewhere) return true;
        } else if (const Range* range = find_range(*group, entry.psid)) {
            if (ssp_within(entry.ssp, range->sspRange)) return true;
        }
    }
    return false;
}

// a subordinate CA's PsidSspRange nests inside the issuer's range for the same PSID
bool range_within(const Vanetza_Security_SspRange_t* sub, const Vanetza_Security_SspRange_t* issuer) {
    if (!issuer || issuer->present == Vanetza_Security_SspRange_PR_all) return true;
    if (!sub || sub->present == Vanetza_Security_SspRange_PR_all) return false;
    if (issuer->present == Vanetza_Security_SspRange_PR_opaque) {
        if (sub->present != Vanetza_Security_SspRange_PR_opaque) return false;
        const auto& subs = sub->choice.opaque.list;
        const auto& issuers = issuer->choice.opaque.list;
        for (int i = 0; i < subs.count; ++i) {
            bool found = false;
            for (int j = 0; j < issuers.count && !found; ++j) {
                found = subs.array[i] && issuers.array[j] && octets_equal(*subs.array[i], *issuers.array[j]);
            }
            if (!found) return false;
        }
        return true;
    }
    if (issuer->present == Vanetza_Security_SspRange_PR_bitmapSspRange) {
        if (sub->present != Vanetza_Security_SspRange_PR_bitmapSspRange) return false;
        const auto& r = issuer->choice.bitmapSspRange;
        const auto& p = sub->choice.bitmapSspRange;
        if (r.sspValue.size != r.sspBitmask.size || p.sspValue.size != p.sspBitmask.size) return false;
        for (std::size_t i = 0; i < r.sspBitmask.size; ++i) {
            const std::uint8_t fixed = r.sspBitmask.buf[i];
            if (!fixed) continue;
            if (i >= p.sspBitmask.size) return false;
            if ((p.sspBitmask.buf[i] & fixed) != fixed) return false;
            if ((p.sspValue.buf[i] & fixed) != (r.sspValue.buf[i] & fixed)) return false;
        }
        return true;
    }
    return false;
}

bool nests(const Groups& sub, const Groups& issuer) {
    for (int i = 0; i < sub.list.count; ++i) {
        const Group* group = sub.list.array[i];
        if (!group) continue;
        if (group->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all) {
            bool found = false;
            for (int j = 0; j < issuer.list.count && !found; ++j) {
                found = issuer.list.array[j] &&
                        issuer.list.array[j]->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all;
            }
            if (!found) return false;
            continue;
        }
        if (group->subjectPermissions.present != Vanetza_Security_SubjectPermissions_PR_explicit) return false;
        const auto& ranges = group->subjectPermissions.choice.Explicit.list;
        for (int k = 0; k < ranges.count; ++k) {
            const Range* range = ranges.array[k];
            if (!range) continue;
            const bool elsewhere = listed_explicitly(issuer, range->psid);
            bool found = false;
            for (int j = 0; j < issuer.list.count && !found; ++j) {
                const Group* candidate = issuer.list.array[j];
                if (!candidate) continue;
                if (candidate->subjectPermissions.present == Vanetza_Security_SubjectPermissions_PR_all) found = !elsewhere;
                else if (const Range* r = find_range(*candidate, range->psid)) found = range_within(range->sspRange, r->sspRange);
            }
            if (!found) return false;
        }
    }
    return true;
}

// chain[0] is the end entity, chain.back() the anchor
bool chain_consistent(const std::vector<const Vanetza_Security_EtsiTs103097Certificate_t*>& chain) {
    if (chain.empty()) return false;
    const auto* app = chain.front()->toBeSigned.appPermissions;
    if (!app) return false;
    for (std::size_t depth = 1; depth < chain.size(); ++depth) {
        const Groups* issuing = chain[depth]->toBeSigned.certIssuePermissions;
        if (!issuing) return false;
        for (int i = 0; i < app->list.count; ++i) {
            if (!app->list.array[i] || !covers(*issuing, *app->list.array[i], depth)) return false;
        }
    }
    for (std::size_t k = 1; k + 1 < chain.size(); ++k) { // subordinate CAs below the anchor
        const Groups* sub = chain[k]->toBeSigned.certIssuePermissions;
        const Groups* issuer = chain[k + 1]->toBeSigned.certIssuePermissions;
        if (!sub || !issuer || !nests(*sub, *issuer)) return false;
    }
    return true;
}

// IEEE Std 1609.2-2025 GeographicRegion (6.4.17): "a certificate is not valid if any part
// of the region indicated in its scope field lies outside the region indicated in the
// scope of its issuer". Geometric issuer regions are decided by the upstream geometry
// (CertificateView::region_is_within). An identifiedRegion issuer (6.4.21 to 6.4.24:
// countryOnly, countryAndRegions, countryAndSubregions) contains an identifiedRegion
// subject when every subject entry lies in an issuer entry of the same country: a whole
// country covers everything in it, regions cover their subregions, lists must nest.
// Whether a circle, rectangle or polygon lies inside a country needs a border database
// this library does not carry; that case follows the station's
// VerificationPolicy::permissive_identified_region, as the location check does.
using Identified = Vanetza_Security_IdentifiedRegion_t;

bool contains_all(const Vanetza_Security_SequenceOfUint8_t& outer, const Vanetza_Security_SequenceOfUint8_t& inner) {
    for (int i = 0; i < inner.list.count; ++i) {
        bool found = false;
        for (int j = 0; j < outer.list.count && !found; ++j) found = inner.list.array[i] && outer.list.array[j] && *inner.list.array[i] == *outer.list.array[j];
        if (!found) return false;
    }
    return true;
}
bool contains_all(const Vanetza_Security_SequenceOfUint16_t& outer, const Vanetza_Security_SequenceOfUint16_t& inner) {
    for (int i = 0; i < inner.list.count; ++i) {
        bool found = false;
        for (int j = 0; j < outer.list.count && !found; ++j) found = inner.list.array[i] && outer.list.array[j] && *inner.list.array[i] == *outer.list.array[j];
        if (!found) return false;
    }
    return true;
}
// region r (with the given subregions, nullptr: the whole region) inside one issuer entry
bool region_in_entry(long country, long region, const Vanetza_Security_SequenceOfUint16_t* subregions, const Identified& entry) {
    switch (entry.present) {
        case Vanetza_Security_IdentifiedRegion_PR_countryOnly:
            return entry.choice.countryOnly == country;
        case Vanetza_Security_IdentifiedRegion_PR_countryAndRegions: {
            if (entry.choice.countryAndRegions.countryOnly != country) return false;
            const auto& regions = entry.choice.countryAndRegions.regions.list;
            for (int j = 0; j < regions.count; ++j) if (regions.array[j] && *regions.array[j] == region) return true;
            return false;
        }
        case Vanetza_Security_IdentifiedRegion_PR_countryAndSubregions: {
            if (entry.choice.countryAndSubregions.country != country || !subregions) return false;
            const auto& entries = entry.choice.countryAndSubregions.regionAndSubregions.list;
            for (int j = 0; j < entries.count; ++j) {
                if (entries.array[j] && entries.array[j]->region == region) return contains_all(entries.array[j]->subregions, *subregions);
            }
            return false;
        }
        default:
            return false;
    }
}
bool identified_within(const Vanetza_Security_SequenceOfIdentifiedRegion_t& inner, const Vanetza_Security_SequenceOfIdentifiedRegion_t& outer) {
    for (int i = 0; i < inner.list.count; ++i) {
        const Identified* entry = inner.list.array[i];
        if (!entry) return false;
        bool covered = false;
        for (int j = 0; j < outer.list.count && !covered; ++j) {
            const Identified* candidate = outer.list.array[j];
            if (!candidate) continue;
            switch (entry->present) {
                case Vanetza_Security_IdentifiedRegion_PR_countryOnly:
                    covered = candidate->present == Vanetza_Security_IdentifiedRegion_PR_countryOnly &&
                              candidate->choice.countryOnly == entry->choice.countryOnly;
                    break;
                case Vanetza_Security_IdentifiedRegion_PR_countryAndRegions: {
                    const auto& regions = entry->choice.countryAndRegions.regions.list;
                    covered = regions.count > 0;
                    for (int r = 0; r < regions.count && covered; ++r)
                        covered = regions.array[r] && region_in_entry(entry->choice.countryAndRegions.countryOnly, *regions.array[r], nullptr, *candidate);
                    break;
                }
                case Vanetza_Security_IdentifiedRegion_PR_countryAndSubregions: {
                    const auto& entries = entry->choice.countryAndSubregions.regionAndSubregions.list;
                    covered = entries.count > 0;
                    for (int r = 0; r < entries.count && covered; ++r)
                        covered = entries.array[r] && region_in_entry(entry->choice.countryAndSubregions.country, entries.array[r]->region,
                                                                       &entries.array[r]->subregions, *candidate);
                    break;
                }
                default:
                    covered = false;
            }
        }
        if (!covered) return false;
    }
    return true;
}
bool region_within(const Vanetza_Security_EtsiTs103097Certificate_t& subject, const Vanetza_Security_EtsiTs103097Certificate_t& issuer,
                   bool permissive_identified_region) {
    const auto* outer = issuer.toBeSigned.region;
    const auto* inner = subject.toBeSigned.region;
    if (!outer) return true;
    if (!inner) return false;
    if (outer->present != Vanetza_Security_GeographicRegion_PR_identifiedRegion)
        return v3::CertificateView(&subject).region_is_within(v3::CertificateView(&issuer)); // upstream geometry
    switch (inner->present) {
        case Vanetza_Security_GeographicRegion_PR_identifiedRegion:
            return identified_within(inner->choice.identifiedRegion, outer->choice.identifiedRegion);
        case Vanetza_Security_GeographicRegion_PR_circularRegion:
        case Vanetza_Security_GeographicRegion_PR_rectangularRegion:
        case Vanetza_Security_GeographicRegion_PR_polygonalRegion:
            return permissive_identified_region; // no border database: policy
        default:
            return false;
    }
}
} // namespace consistency
} // namespace

bool chain_permissions_consistent(const std::vector<const Certificate*>& chain) {
    std::vector<const Vanetza_Security_EtsiTs103097Certificate_t*> raw;
    for (const auto* certificate : chain) {
        if (!certificate || !certificate->content()) return false;
        raw.push_back(certificate->content());
    }
    return consistency::chain_consistent(raw);
}

bool region_within(const Certificate& subject, const Certificate& issuer, bool permissive_identified_region) {
    if (!subject.content() || !issuer.content()) return false;
    return consistency::region_within(*subject.content(), *issuer.content(), permissive_identified_region);
}

// ---- SecurityEntity ---------------------------------------------------------

#if VIDF_SECURITY_VERIFY
namespace {
// Issuer lookup over the provisioned authorities and the ones learned by P2P distribution.
class CombinedIssuerLookup : public v3::IssuerLookup {
public:
    explicit CombinedIssuerLookup(const v3::IssuerLookup& provisioned) : provisioned_(provisioned) {}
    const Certificate* find_issuer(const HashedId8& digest) const override {
        if (const auto* found = provisioned_.find_issuer(digest)) return found;
        for (const auto& learned : learned_) {
            if (learned.calculate_digest() == digest) return &learned;
        }
        return nullptr;
    }
    std::deque<Certificate> learned_;
private:
    const v3::IssuerLookup& provisioned_;
};


// TS 102 940 clause 6 chain: the upstream validator checks anchoring, time, ITS-AID and
// assurance consistency; this adds the certificate signatures up the chain (IEEE Std
// 1609.2 clause 5.3.1), the permission consistency of clause 5.1.2 and the region
// consistency of 6.4.17 (above; the upstream region check knows no identifiedRegion
// issuer and is switched off), remembering tickets already verified.
class ChainValidator {
public:
    using Verdict = v3::CertificateValidator::Verdict;
    ChainValidator(Backend& backend, v3::DefaultCertificateValidator& base, const v3::IssuerLookup& issuers) :
        backend_(backend), base_(base), issuers_(issuers) {}
    std::size_t capacity = 64;
    bool permissive_identified_region = true;
    Verdict valid_for_signing(const Vanetza_Security_EtsiTs103097Certificate_t& signing_cert, ItsAid its_aid) {
        const v3::CertificateView view { &signing_cert };
        const auto verdict = base_.valid_for_signing(view, its_aid);
        if (verdict != Verdict::Valid) return verdict;
        const auto digest = view.calculate_digest();
        if (!digest) return Verdict::Untrusted;
        if (verified_.count(*digest)) return Verdict::Valid;
        // walk up to a self-signed anchor, verifying every signature on the way
        std::vector<const Vanetza_Security_EtsiTs103097Certificate_t*> chain {&signing_cert};
        bool anchored = false;
        for (unsigned depth = 0; depth < 4 && !anchored; ++depth) {
            const Vanetza_Security_EtsiTs103097Certificate_t* subject = chain.back();
            const v3::CertificateView subject_view { subject };
            if (subject_view.issuer_is_self()) {
                if (!verify_certificate_signature(backend_, *subject, nullptr)) return Verdict::Untrusted;
                anchored = true;
                break;
            }
            const auto issuer_digest = subject_view.issuer_digest();
            const Certificate* issuer = issuer_digest ? issuers_.find_issuer(*issuer_digest) : nullptr;
            if (!issuer || !issuer->content()) return Verdict::Untrusted;
            if (!verify_certificate_signature(backend_, *subject, issuer)) return Verdict::Untrusted;
            chain.push_back(issuer->content());
            anchored = issuer->issuer_is_self(); // the anchor was provisioned by the application
        }
        if (!anchored) return Verdict::Untrusted;
        if (chain.size() > 1 && !consistency::chain_consistent(chain)) return Verdict::InconsistentChain;
        for (std::size_t k = 0; k + 1 < chain.size(); ++k) {
            if (!consistency::region_within(*chain[k], *chain[k + 1], permissive_identified_region)) return Verdict::InconsistentChain;
        }
        if (verified_.size() >= capacity) verified_.clear();
        verified_.insert(*digest);
        return Verdict::Valid;
    }
private:
    Backend& backend_;
    v3::DefaultCertificateValidator& base_;
    const v3::IssuerLookup& issuers_;
    std::unordered_set<HashedId8> verified_;
};
} // namespace
#endif

class SecurityEntity::Impl {
public:
    Runtime& runtime;
    Backend& backend;
    const TrustConfiguration& trust;
    CertificatePool& pool;
    v3::DefaultLocationChecker location_checker;
    v3::DefaultCertificateValidator validator;
    Ts103097SignHeaderPolicy policy;
    v3::StraightSignService sign_service;
    IdentityManager identity;
    std::deque<SecurityEvent> events;
    std::size_t event_capacity = 16;
    Statistics stats;
    VerificationPolicy verification;
#if VIDF_SECURITY_VERIFY
    CombinedIssuerLookup issuers;
    ChainValidator chain;
    v3::CertificateCache cache;
    std::deque<std::pair<HashedId8, v3::Time64>> accepted; // replay window
#endif

    Impl(Runtime& rt, PositionProvider& position, Backend& be, CertificatePool& certificates,
         const TrustConfiguration& tc) :
        runtime(rt), backend(be), trust(tc), pool(certificates), policy(rt, position, certificates, tc),
        sign_service(certificates, be, policy, validator), identity(rt, certificates)
#if VIDF_SECURITY_VERIFY
        , issuers(tc.issuers()), chain(be, validator, issuers)
#endif
    {
        validator.use_runtime(&rt);
        validator.use_position_provider(&position);
        validator.use_location_checker(&location_checker);
        validator.use_trust_store(&tc.roots());
        location_checker.set_permissive_identified_region(verification.permissive_identified_region);
#if VIDF_SECURITY_VERIFY
        validator.use_issuer_lookup(&issuers);
        // upstream's is_within() has no identifiedRegion issuer case (an EU root would make
        // every chain inconsistent); ChainValidator applies the region rule of 6.4.17 instead
        validator.disable_region_consistency_checks(true);
        chain.permissive_identified_region = verification.permissive_identified_region;
#else
        validator.use_issuer_lookup(&tc.issuers());
#endif
        identity.on_committed([this](const Identifier&) { policy.reset_after_identifier_change(); });
    }

#if VIDF_SECURITY_VERIFY
    // TS 103 097 clause 7.1.1: a requestedCertificate carries a CA certificate answering a
    // P2P request; keep it once its signature chains to a provisioned or learned issuer.
    void learn_authority(const Vanetza_Security_Certificate* asn) {
        if (!asn) return;
        Certificate candidate { *reinterpret_cast<const Vanetza_Security_EtsiTs103097Certificate_t*>(asn) };
        if (!candidate.is_ca_certificate() || candidate.issuer_is_self()) return;
        const auto digest = candidate.calculate_digest();
        if (!digest || issuers.find_issuer(*digest)) return; // known already
        const auto issuer_digest = candidate.issuer_digest();
        const Certificate* issuer = issuer_digest ? issuers.find_issuer(*issuer_digest) : nullptr;
        if (!issuer || !verify_certificate_signature(backend, candidate, issuer)) return;
        while (issuers.learned_.size() >= std::max<std::size_t>(1, verification.learned_authority_limit)) issuers.learned_.pop_front();
        issuers.learned_.push_back(std::move(candidate));
        ++stats.learned_authorities;
    }

    // IEEE Std 1609.2 clause 5.2 processing of an EtsiTs103097Data-Signed, following the
    // upstream StraightVerifyService::verify(const v3::SecuredMessage&) step by step (that
    // translation unit also carries the v2 path and is not compiled into the port): signer
    // lookup (cache or inline certificate), P2P certificate distribution hooks of TS 103 097
    // clause 7.1.1 through the header policy, ticket validity through the chain validator,
    // message hash with the signing certificate (clause 5.3.1) and the ECDSA check.
    VerifyConfirm verify_signed(const v3::SecuredMessage& msg) {
        VerifyConfirm confirm;
        confirm.report = VerificationReport::Incompatible_Protocol;
        confirm.its_aid = msg.its_aid(); // header value until verified
        const auto signature = msg.signature();
        if (!signature) { confirm.report = VerificationReport::Unsigned_Message; return confirm; }
        const auto signer_identifier = msg.signer_identifier();
        const auto maybe_digest = v3::get_certificate_id(signer_identifier);
        const ItsAid its_aid = msg.its_aid();
        if (maybe_digest) {
            // "known" station tracking: a CAM from a station seen for the first time makes the
            // next own CAM carry the certificate (clause 7.1.1)
            const bool was_unknown = cache.announce(*maybe_digest);
            if (was_unknown && its_aid == aid::CA) policy.request_certificate();
        }
        if (its_aid == aid::CA) {
            const auto& header = msg->content->choice.signedData->tbsData->headerInfo;
            if (header.inlineP2pcdRequest) {
                for (int i = 0; i < header.inlineP2pcdRequest->list.count; ++i)
                    policy.enqueue_p2p_request(create_hashed_id3(*header.inlineP2pcdRequest->list.array[i]));
            }
            if (header.requestedCertificate) {
                if (const auto included = v3::calculate_digest(*reinterpret_cast<const Vanetza_Security_EtsiTs103097Certificate_t*>(header.requestedCertificate)))
                    policy.discard_p2p_request(truncate(*included));
            }
        }
        const v3::asn1::Certificate* certificate = nullptr;
        if (const auto* const* inline_cert = boost::get<const v3::asn1::Certificate*>(&signer_identifier)) {
            certificate = *inline_cert;
        } else if (maybe_digest) {
            if (const auto* cached = cache.lookup(*maybe_digest)) certificate = cached->content();
        }
        if (!certificate) {
            if (its_aid == aid::CA && maybe_digest) policy.request_unrecognized_certificate(*maybe_digest);
            confirm.report = VerificationReport::Signer_Certificate_Not_Found;
            return confirm;
        }
        const v3::CertificateView view { certificate };
        const auto verdict = chain.valid_for_signing(*certificate, its_aid);
        if (verdict != ChainValidator::Verdict::Valid) {
            // an AT issued by an unknown AA: ask for the AA (clause 7.1.1 inlineP2pcdRequest)
            if (const auto aa = view.issuer_digest()) {
                if (!issuers.find_issuer(*aa) && !cache.is_known(*aa)) policy.request_unrecognized_certificate(*aa);
            }
            // TS 102 723-8 V1.1.1 Table 27 report codes: INVALID_CERTIFICATE for the certificate
            // itself, INCONSISTENT_CHAIN when the chain's permissions do not fit (IEEE 1609.2 5.1.2)
            confirm.report = VerificationReport::Invalid_Certificate;
            switch (verdict) {
                case ChainValidator::Verdict::Expired: confirm.certificate_validity = CertificateInvalidReason::Off_Time_Period; break;
                case ChainValidator::Verdict::Untrusted: confirm.certificate_validity = CertificateInvalidReason::Unknown_Signer; break;
                case ChainValidator::Verdict::InconsistentChain:
                    confirm.report = VerificationReport::Inconsistent_Chain;
                    confirm.certificate_validity = CertificateInvalidReason::Inconsistent_With_Signer;
                    break;
                case ChainValidator::Verdict::OutsideRegion: confirm.certificate_validity = CertificateInvalidReason::Off_Region; break;
                case ChainValidator::Verdict::InsufficientPermission: confirm.certificate_validity = CertificateInvalidReason::Insufficient_ITS_AID; break;
                default: break;
            }
            return confirm;
        }
        const auto public_key = v3::get_public_key(*certificate);
        if (!public_key) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            return confirm;
        }
        const ByteBuffer digest = v3::calculate_message_hash(backend, msg.hash_id(), msg.signing_payload(), view);
        if (!backend.verify_digest(*public_key, digest, *signature)) {
            confirm.report = VerificationReport::False_Signature;
            return confirm;
        }
        confirm.its_aid = its_aid;
        confirm.permissions = v3::get_app_permissions(*certificate, its_aid);
        confirm.certificate_id = maybe_digest ? maybe_digest : view.calculate_digest();
        confirm.report = VerificationReport::Success;
        if (confirm.certificate_id && v3::contains_certificate(signer_identifier) && !cache.lookup(*confirm.certificate_id)) {
            if (its_aid == aid::CA) policy.request_certificate(); // clause 7.1.1: first CAM from this station
            cache.store(v3::Certificate { *certificate });
        }
        return confirm;
    }

    DecapConfirm verify(const v3::SecuredMessage& msg, const DecapRequest& request) {
        const auto profile = check_profile(msg);
        if (profile != VerificationReport::Success) {
            ++stats.rejected_profile;
            DecapConfirm confirm;
            confirm.report = profile;
            confirm.its_aid = msg.its_aid();
            confirm.plaintext_payload = get_payload_copy(request.sec_packet);
            return confirm;
        }
        if (msg->content->choice.signedData->tbsData->headerInfo.requestedCertificate)
            learn_authority(msg->content->choice.signedData->tbsData->headerInfo.requestedCertificate);
        auto verified = verify_signed(msg);
        if (verified.report == VerificationReport::Success) {
            // generationTime plausibility and replay (VerificationPolicy)
            const auto generation = msg.generation_time();
            const auto now = v3::convert_time64(runtime.now());
            const auto future = static_cast<v3::Time64>(std::chrono::duration_cast<std::chrono::microseconds>(verification.generation_time_future_tolerance).count());
            const auto age = static_cast<v3::Time64>(std::chrono::duration_cast<std::chrono::microseconds>(verification.generation_time_max_age).count());
            if (!generation || *generation > now + future || *generation + age < now) {
                ++stats.rejected_time;
                verified.report = VerificationReport::Invalid_Timestamp;
            } else if (verification.replay_window && verified.certificate_id) {
                const std::pair<HashedId8, v3::Time64> key {*verified.certificate_id, *generation};
                if (std::find(accepted.begin(), accepted.end(), key) != accepted.end()) {
                    ++stats.replayed;
                    verified.report = VerificationReport::Duplicate_Message;
                } else {
                    while (accepted.size() >= verification.replay_window) accepted.pop_front();
                    accepted.push_back(key);
                }
            }
        }
        switch (verified.report) {
            case VerificationReport::Success: ++stats.verified; break;
            case VerificationReport::Invalid_Timestamp: case VerificationReport::Duplicate_Message: break; // counted above
            case VerificationReport::Signer_Certificate_Not_Found: case VerificationReport::Unsupported_Signer_Identifier_Type: ++stats.rejected_signer; break;
            case VerificationReport::False_Signature: ++stats.rejected_signature; break;
            default: ++stats.rejected_certificate; break;
        }
        if (cache.size() > verification.certificate_cache_limit) cache = v3::CertificateCache {}; // bounded on the device
        return DecapConfirm::from(std::move(verified), request.sec_packet);
    }
#endif
};

SecurityEntity::SecurityEntity(Runtime& rt, PositionProvider& position, Backend& backend, CertificatePool& pool,
                               const TrustConfiguration& trust) :
    impl_(std::make_unique<Impl>(rt, position, backend, pool, trust)) {}
SecurityEntity::~SecurityEntity() = default;

EncapConfirm SecurityEntity::encapsulate_packet(EncapRequest&& request) {
    // Table 24 -> Table 25. Fail closed without a ticket or during PREPARE..COMMIT.
    auto& stats = impl_->stats;
    if (impl_->pool.empty()) {
        ++stats.refused_no_ticket;
        return EncapConfirm::from(SignConfirm::failure(SignConfirmError::No_Certificate));
    }
    if (impl_->identity.change_pending()) {
        ++stats.refused_change_pending;
        return EncapConfirm::from(SignConfirm::failure(SignConfirmError::No_Certificate));
    }
    try {
        auto confirm = dispatch(std::move(request), &impl_->sign_service);
        if (confirm.secured_message()) ++stats.signed_messages;
        else ++stats.refused_permission; // validator verdict != Valid for this ITS-AID
        return confirm;
    } catch (const std::exception&) {
        ++stats.failed;
        return EncapConfirm::from(SignConfirm::failure(SignConfirmError::Unspecified));
    }
}
const SecurityEntity::Statistics& SecurityEntity::statistics() const { return impl_->stats; }

DecapConfirm SecurityEntity::decapsulate_packet(DecapRequest&& request) {
    // Table 26 -> Table 27.
    struct Visitor : boost::static_visitor<DecapConfirm> {
        Impl& impl;
        const DecapRequest& request;
        Visitor(Impl& i, const DecapRequest& r) : impl(i), request(r) {}
        DecapConfirm operator()(const v2::SecuredMessage& msg) const {
            DecapConfirm confirm;
            confirm.report = VerificationReport::Incompatible_Protocol; // TS 103 097 v1.x envelope
            confirm.its_aid = 0;
            confirm.plaintext_payload = get_payload_copy(SecuredMessage {msg});
            return confirm;
        }
        DecapConfirm operator()(const v3::SecuredMessage& msg) const {
#if VIDF_SECURITY_VERIFY
            try {
                return impl.verify(msg, request);
            } catch (const std::exception&) {
                ++impl.stats.failed;
                DecapConfirm confirm;
                confirm.report = VerificationReport::Incompatible_Protocol; // malformed structure
                confirm.its_aid = msg.its_aid();
                return confirm;
            }
#else
            // Without verification (GAP-SEC-001) the report never claims success.
            (void)impl;
            DecapConfirm confirm;
            confirm.report = msg.is_signed() ? VerificationReport::Configuration_Problem
                                             : VerificationReport::Unsigned_Message;
            confirm.its_aid = msg.its_aid(); // header value, not verified
            confirm.certificate_id = msg.certificate_id();
            confirm.plaintext_payload = msg.payload();
            return confirm;
#endif
        }
    };
    Visitor visitor(*impl_, request);
    return request.sec_packet.apply_visitor(visitor);
}
void SecurityEntity::set_verification_policy(const VerificationPolicy& policy) {
    impl_->verification = policy;
    impl_->location_checker.set_permissive_identified_region(policy.permissive_identified_region);
#if VIDF_SECURITY_VERIFY
    impl_->chain.permissive_identified_region = policy.permissive_identified_region;
#endif
#if VIDF_SECURITY_VERIFY
    impl_->chain.capacity = std::max<std::size_t>(1, policy.verified_chain_cache);
#endif
}
const VerificationPolicy& SecurityEntity::verification_policy() const { return impl_->verification; }
const std::deque<Certificate>& SecurityEntity::learned_authorities() const {
#if VIDF_SECURITY_VERIFY
    return impl_->issuers.learned_;
#else
    static const std::deque<Certificate> none;
    return none;
#endif
}

void SecurityEntity::log_security_event(SecurityEvent event) {
    while (impl_->events.size() >= impl_->event_capacity) impl_->events.pop_front();
    impl_->events.push_back(std::move(event));
}
std::deque<SecurityEvent> SecurityEntity::drain_security_events() {
    std::deque<SecurityEvent> out;
    out.swap(impl_->events);
    return out;
}
void SecurityEntity::set_security_event_capacity(std::size_t capacity) {
    impl_->event_capacity = std::max<std::size_t>(1, capacity);
    while (impl_->events.size() > impl_->event_capacity) impl_->events.pop_front();
}
IdChangeService& SecurityEntity::id_change() { return impl_->identity; }
const IdChangeService& SecurityEntity::id_change() const { return impl_->identity; }
IdentityManager& SecurityEntity::identity_manager() { return impl_->identity; }
Ts103097SignHeaderPolicy& SecurityEntity::header_policy() { return impl_->policy; }
v3::DefaultCertificateValidator& SecurityEntity::validator() { return impl_->validator; }
CertificatePool& SecurityEntity::certificates() { return impl_->pool; }

} // namespace vanetza_idf::security
