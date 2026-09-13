#include <vanetza_idf/security.hpp>
#include <vanetza/security/encap_service.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
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

// ---- SecurityEntity ---------------------------------------------------------

class SecurityEntity::Impl {
public:
    Runtime& runtime;
    CertificatePool& pool;
    v3::AllowLocationChecker location_checker; // region checks need a country database: not supplied here
    v3::DefaultCertificateValidator validator;
    Ts103097SignHeaderPolicy policy;
    v3::StraightSignService sign_service;
    IdentityManager identity;
    std::deque<SecurityEvent> events;
    std::size_t event_capacity = 16;
    Statistics stats;

    Impl(Runtime& rt, PositionProvider& position, Backend& backend, CertificatePool& certificates,
         const TrustConfiguration& trust) :
        runtime(rt), pool(certificates), policy(rt, position, certificates, trust),
        sign_service(certificates, backend, policy, validator), identity(rt, certificates) {
        validator.use_runtime(&rt);
        validator.use_position_provider(&position);
        validator.use_location_checker(&location_checker);
        validator.use_trust_store(&trust.roots());
        validator.use_issuer_lookup(&trust.issuers());
        identity.on_committed([this](const Identifier&) { policy.reset_after_identifier_change(); });
    }
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
    // Table 26 -> Table 27 without verification (GAP-SEC-001): the report never claims success.
    struct Visitor : boost::static_visitor<DecapConfirm> {
        DecapConfirm operator()(const v2::SecuredMessage& msg) const {
            DecapConfirm confirm;
            confirm.report = VerificationReport::Incompatible_Protocol; // TS 103 097 v1.x envelope
            confirm.its_aid = 0;
            confirm.plaintext_payload = get_payload_copy(SecuredMessage {msg});
            return confirm;
        }
        DecapConfirm operator()(const v3::SecuredMessage& msg) const {
            DecapConfirm confirm;
            confirm.report = msg.is_signed() ? VerificationReport::Configuration_Problem
                                             : VerificationReport::Unsigned_Message;
            confirm.its_aid = msg.its_aid(); // header value, not verified
            confirm.certificate_id = msg.certificate_id();
            confirm.plaintext_payload = msg.payload();
            return confirm;
        }
    };
    Visitor visitor;
    return request.sec_packet.apply_visitor(visitor);
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
