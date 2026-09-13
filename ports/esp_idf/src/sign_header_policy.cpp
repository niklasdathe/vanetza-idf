// Signer identifier and header selection per TS 103 097 V2.2.1 clause 7.1 and
// TS 103 300-3 V2.3.1 clause 6.5.3. See the class comment in security.hpp.
#include <vanetza_idf/security.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/peer_request_tracker.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <chrono>
#include <map>

namespace vanetza::security::v3 {
// Defined in the upstream sign_header_policy.cpp translation unit (not declared in its header):
// ThreeDLocation from a PositionFix (IEEE 1609.2 clause 6.3.10 encoding).
asn1::ThreeDLocation build_location(const PositionFix& fix);
}

namespace vanetza_idf::security {
using namespace vanetza;
using namespace vanetza::security;

class Ts103097SignHeaderPolicy::Impl {
public:
    const Runtime& runtime;
    PositionProvider& positioning;
    CertificatePool& pool;
    const TrustConfiguration& trust;
    // CAM, clause 7.1.1
    boost::optional<Clock::time_point> cam_last_certificate;
    bool cam_certificate_requested = false;
    PeerRequestTracker incoming_requests; // inlineP2pcdRequest digests received from peers
    PeerRequestTracker outgoing_requests; // certificates unknown to us
    // VAM, TS 103 300-3 clause 6.5.3
    boost::optional<Clock::time_point> vam_last_certificate;
    bool new_cam_signer = false;
    // generic profile: per ITS-AID
    std::map<ItsAid, Clock::time_point> generic_last_certificate;

    Impl(const Runtime& rt, PositionProvider& pp, CertificatePool& certificates, const TrustConfiguration& t) :
        runtime(rt), positioning(pp), pool(certificates), trust(t) {}

    static constexpr std::chrono::milliseconds one_second {1000};
    static constexpr std::chrono::milliseconds half_second {500};

    template<class Optional>
    static bool elapsed(const Optional& last, Clock::time_point now, std::chrono::milliseconds interval) {
        return !last || now - *last >= interval;
    }

    void cam(const SignRequest&, v3::SecuredMessage& message, const Certificate& at, Clock::time_point now) {
        const auto digest = at.calculate_digest();
        // Inline P2PCD request naming our own AT: include the certificate immediately.
        if (digest && incoming_requests.is_pending(truncate(*digest))) {
            cam_certificate_requested = true;
            incoming_requests.discard_request(truncate(*digest));
        }
        bool full_certificate = cam_certificate_requested || elapsed(cam_last_certificate, now, one_second);
        if (full_certificate) {
            message.set_signer_identifier(at);
            cam_last_certificate = now; // "the timer for the next inclusion ... shall be restarted"
            cam_certificate_requested = false;
        } else {
            message.set_signer_identifier(*digest);
        }
        // Digests of certificates unknown to this station (clause 7.1.1, inlineP2pcdRequest).
        message.set_inline_p2pcd_request(outgoing_requests.all());
        // requestedCertificate: a known CA certificate that a peer asked for, only while our
        // signer is the digest ("unless the component signer ... is of choice certificate").
        if (!full_certificate) {
            while (auto requested = incoming_requests.next_one()) {
                for (const auto& authority : trust.authorities()) {
                    const auto authority_digest = authority.calculate_digest();
                    if (authority_digest && truncate(*authority_digest) == *requested) {
                        message.set_requested_certificate(authority);
                        return;
                    }
                }
            }
        }
    }

    void denm(v3::SecuredMessage& message, const Certificate& at) {
        message.set_signer_identifier(at);
        message.set_generation_location(v3::build_location(positioning.position_fix()));
    }

    void vam(const SignRequest& request, v3::SecuredMessage& message, const Certificate& at, Clock::time_point now) {
        const bool cluster = request.context_information == context::vam_cluster;
        bool attach;
        if (cluster) {
            attach = elapsed(vam_last_certificate, now, half_second);
        } else {
            attach = new_cam_signer || elapsed(vam_last_certificate, now, one_second);
        }
        if (attach) {
            message.set_signer_identifier(at);
            vam_last_certificate = now;
            new_cam_signer = false;
        } else if (auto digest = at.calculate_digest()) {
            message.set_signer_identifier(*digest);
        } else {
            message.set_signer_identifier(at);
        }
    }

    void generic(ItsAid aid, v3::SecuredMessage& message, const Certificate& at, Clock::time_point now) {
        auto it = generic_last_certificate.find(aid);
        const auto digest = at.calculate_digest();
        if (it == generic_last_certificate.end() || now - it->second >= one_second || !digest) {
            message.set_signer_identifier(at);
            generic_last_certificate[aid] = now;
        } else {
            message.set_signer_identifier(*digest);
        }
    }
};

Ts103097SignHeaderPolicy::Ts103097SignHeaderPolicy(const Runtime& rt, PositionProvider& pp, CertificatePool& pool,
                                                   const TrustConfiguration& trust) :
    impl_(std::make_unique<Impl>(rt, pp, pool, trust)) {}
Ts103097SignHeaderPolicy::~Ts103097SignHeaderPolicy() = default;

void Ts103097SignHeaderPolicy::prepare_header(const SignRequest& request, v3::SecuredMessage& message) {
    const auto now = impl_->runtime.now();
    // Clause 5.2: psid and generationTime always present.
    message.set_its_aid(request.its_aid);
    message.set_generation_time(v2::convert_time64(now));
    const Certificate& at = impl_->pool.own_certificate();
    if (request.self_signed) {
        // TS 102 941 clause 6.2.3.2 inner enrolment structures are self-signed.
        message.set_signer_identifier_self();
        return;
    }
    switch (request.its_aid) {
        case aid::CA: impl_->cam(request, message, at, now); break;
        case aid::DEN: impl_->denm(message, at); break;
        case aid::VRU: impl_->vam(request, message, at, now); break;
        default: impl_->generic(request.its_aid, message, at, now); break;
    }
}

void Ts103097SignHeaderPolicy::request_unrecognized_certificate(HashedId8 id) {
    impl_->outgoing_requests.add_request(truncate(id));
}
void Ts103097SignHeaderPolicy::request_certificate() { impl_->cam_certificate_requested = true; }
void Ts103097SignHeaderPolicy::enqueue_p2p_request(HashedId3 id) { impl_->incoming_requests.add_request(id); }
void Ts103097SignHeaderPolicy::discard_p2p_request(HashedId3 id) { impl_->incoming_requests.discard_request(id); }
void Ts103097SignHeaderPolicy::report_new_cam_signer() { impl_->new_cam_signer = true; }
void Ts103097SignHeaderPolicy::reset_after_identifier_change() {
    impl_->cam_last_certificate = boost::none;
    impl_->cam_certificate_requested = false;
    impl_->vam_last_certificate = boost::none;
    impl_->generic_last_certificate.clear();
}
} // namespace vanetza_idf::security
