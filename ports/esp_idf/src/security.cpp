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

// TS 102 940 clause 6 chain: the upstream validator checks anchoring, time, permission,
// assurance and region consistency; this adds the certificate signatures up the chain
// (IEEE Std 1609.2 clause 5.3.1), remembering tickets already verified.
class ChainValidator {
public:
    using Verdict = v3::CertificateValidator::Verdict;
    ChainValidator(Backend& backend, v3::DefaultCertificateValidator& base, const v3::IssuerLookup& issuers) :
        backend_(backend), base_(base), issuers_(issuers) {}
    std::size_t capacity = 64;
    Verdict valid_for_signing(const Vanetza_Security_EtsiTs103097Certificate_t& signing_cert, ItsAid its_aid) {
        const v3::CertificateView view { &signing_cert };
        const auto verdict = base_.valid_for_signing(view, its_aid);
        if (verdict != Verdict::Valid) return verdict;
        const auto digest = view.calculate_digest();
        if (!digest) return Verdict::Untrusted;
        if (verified_.count(*digest)) return Verdict::Valid;
        // walk up to a self-signed anchor, verifying every signature on the way
        const Vanetza_Security_EtsiTs103097Certificate_t* subject = &signing_cert;
        for (unsigned depth = 0; depth < 4; ++depth) {
            const v3::CertificateView subject_view { subject };
            if (subject_view.issuer_is_self()) {
                if (!verify_certificate_signature(backend_, *subject, nullptr)) return Verdict::Untrusted;
                break;
            }
            const auto issuer_digest = subject_view.issuer_digest();
            const Certificate* issuer = issuer_digest ? issuers_.find_issuer(*issuer_digest) : nullptr;
            if (!issuer || !issuer->content()) return Verdict::Untrusted;
            if (!verify_certificate_signature(backend_, *subject, issuer)) return Verdict::Untrusted;
            if (issuer->issuer_is_self()) break; // the anchor was provisioned by the application
            subject = issuer->content();
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
        if (chain.valid_for_signing(*certificate, its_aid) != ChainValidator::Verdict::Valid) {
            // an AT issued by an unknown AA: ask for the AA (clause 7.1.1 inlineP2pcdRequest)
            if (const auto aa = view.issuer_digest()) {
                if (!issuers.find_issuer(*aa) && !cache.is_known(*aa)) policy.request_unrecognized_certificate(*aa);
            }
            confirm.report = VerificationReport::Invalid_Certificate;
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
