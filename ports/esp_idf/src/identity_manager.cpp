// TS 102 723-8 V1.1.1 clause 6.3 identifier-change procedures over one pool of
// authorization tickets. See id_change.hpp and security.hpp for the contracts.
#include <vanetza_idf/security.hpp>
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace vanetza_idf::security {
using namespace vanetza;

class IdentityManager::Impl : public std::enable_shared_from_this<IdentityManager::Impl> {
public:
    struct Subscription { IdChangeHook hook; ByteBuffer data; };
    struct Round {
        std::uint64_t id;
        IdChangeCommand phase; // PREPARE or COMMIT
        Identifier new_identifier;
        std::set<SubscriptionHandle> outstanding;
    };

    Runtime& runtime;
    CertificatePool& pool;
    std::map<SubscriptionHandle, Subscription> subscriptions;
    SubscriptionHandle next_subscription = 1;
    std::map<LockHandle, Clock::time_point> locks;
    LockHandle next_lock = 1;
    std::unique_ptr<Round> round;
    std::uint64_t round_counter = 0;
    bool pending_trigger = false;
    Clock::duration response_timeout = std::chrono::milliseconds(500);
    std::function<void(const Identifier&)> committed;
    Statistics stats;
    unsigned notify_depth = 0; // hooks run re-entrantly; phase changes wait until delivery completed
    char round_timer_scope = 0;
    char lock_timer_scope = 0;

    Impl(Runtime& rt, CertificatePool& p) : runtime(rt), pool(p) {}

    Identifier current() const {
        const auto* ticket = pool.current();
        return ticket ? ticket->digest : Identifier {};
    }

    bool locked() const { return !locks.empty(); }

    // Table 13 return_code carrier handed to hooks for PREPARE and COMMIT.
    class Responder : public IdChangeResponder {
    public:
        Responder(std::weak_ptr<Impl> owner, std::uint64_t round, SubscriptionHandle handle) :
            owner_(std::move(owner)), round_(round), handle_(handle) {}
        void respond(bool return_code) override {
            if (auto impl = owner_.lock()) impl->handle_response(round_, handle_, return_code);
        }
    private:
        std::weak_ptr<Impl> owner_;
        std::uint64_t round_;
        SubscriptionHandle handle_;
    };

    // Deliver a command to every current subscriber; hooks may respond, unsubscribe or
    // subscribe re-entrantly, so iterate over a snapshot and re-check membership.
    void notify(IdChangeCommand command, const Identifier& id, bool expect_response) {
        std::vector<SubscriptionHandle> handles;
        for (const auto& entry : subscriptions) handles.push_back(entry.first);
        if (expect_response && round) round->outstanding.insert(handles.begin(), handles.end());
        const auto round_id = round ? round->id : 0;
        ++notify_depth;
        for (auto handle : handles) {
            // An abort raised by an earlier hook ends this round: nobody else gets PREPARE/COMMIT.
            if (expect_response && (!round || round->id != round_id)) break;
            auto it = subscriptions.find(handle);
            if (it == subscriptions.end()) {
                if (round && round->id == round_id) round->outstanding.erase(handle);
                continue;
            }
            std::shared_ptr<IdChangeResponder> responder;
            if (expect_response) responder = std::make_shared<Responder>(weak_from_this(), round_id, handle);
            IdChangeHook hook = it->second.hook;
            ByteBuffer data = it->second.data;
            hook(command, id, data, responder);
        }
        --notify_depth;
        if (expect_response && notify_depth == 0 && round && round->id == round_id) {
            if (round->outstanding.empty()) advance();
            else arm_round_timer();
        }
    }

    void arm_round_timer() {
        runtime.cancel(&round_timer_scope);
        runtime.schedule(response_timeout, [this](Clock::time_point) { on_round_timeout(); }, &round_timer_scope);
    }

    void try_start() {
        if (!pending_trigger || locked() || round) return;
        const auto* next = pool.next_valid(runtime.now());
        pending_trigger = false;
        if (!next) return; // nothing to change to; trigger() already reported this
        round = std::make_unique<Round>(Round {++round_counter, IdChangeCommand::PREPARE, next->digest, {}});
        notify(IdChangeCommand::PREPARE, round->new_identifier, true); // advances or arms the timer itself
    }

    void handle_response(std::uint64_t round_id, SubscriptionHandle handle, bool return_code) {
        if (!round || round->id != round_id) return;
        if (round->outstanding.erase(handle) == 0) return;
        if (!return_code) {
            if (round->phase == IdChangeCommand::PREPARE) { abort(); return; }
            ++stats.commit_failures; // COMMIT cannot be rolled back (Figure 11); recorded
        }
        if (round->outstanding.empty() && notify_depth == 0) advance();
    }

    void advance() {
        runtime.cancel(&round_timer_scope);
        if (round->phase == IdChangeCommand::PREPARE) {
            round->phase = IdChangeCommand::COMMIT;
            pool.select(round->new_identifier);
            notify(IdChangeCommand::COMMIT, round->new_identifier, true); // finishes or arms the timer
        } else {
            finish();
        }
    }

    void finish() {
        runtime.cancel(&round_timer_scope);
        const Identifier id = round->new_identifier;
        round.reset();
        ++stats.committed;
        if (committed) committed(id);
        try_start(); // a trigger queued during this round
    }

    void abort() {
        runtime.cancel(&round_timer_scope);
        const Identifier id = round->new_identifier;
        round.reset();
        ++stats.aborted;
        notify(IdChangeCommand::ABORT, id, false); // Figures 12/13
    }

    void on_round_timeout() {
        if (!round) return;
        ++stats.timed_out;
        if (round->phase == IdChangeCommand::PREPARE) {
            abort();
        } else {
            stats.commit_failures += static_cast<unsigned>(round->outstanding.size());
            finish();
        }
    }

    void arm_lock_timer() {
        runtime.cancel(&lock_timer_scope);
        if (locks.empty()) return;
        Clock::time_point earliest = locks.begin()->second;
        for (const auto& lock : locks) earliest = std::min(earliest, lock.second);
        runtime.schedule(earliest, [this](Clock::time_point) { on_lock_timer(); }, &lock_timer_scope);
    }

    void on_lock_timer() {
        const auto now = runtime.now();
        for (auto it = locks.begin(); it != locks.end();) {
            if (it->second <= now) it = locks.erase(it); else ++it;
        }
        arm_lock_timer();
        try_start();
    }
};

IdentityManager::IdentityManager(Runtime& rt, CertificatePool& pool) : impl_(std::make_shared<Impl>(rt, pool)) {}

IdentityManager::~IdentityManager() {
    impl_->runtime.cancel(&impl_->round_timer_scope);
    impl_->runtime.cancel(&impl_->lock_timer_scope);
    impl_->round.reset();
    impl_->notify(IdChangeCommand::DEREG, impl_->current(), false); // Figure 15
    impl_->subscriptions.clear();
}

SubscriptionHandle IdentityManager::subscribe(IdChangeHook hook, ByteBuffer subscriber_data) {
    const auto handle = impl_->next_subscription++;
    impl_->subscriptions.emplace(handle, Impl::Subscription {std::move(hook), std::move(subscriber_data)});
    return handle;
}

Result IdentityManager::unsubscribe(SubscriptionHandle handle) {
    if (impl_->subscriptions.erase(handle) == 0) return Result::invalid_argument;
    if (impl_->round && impl_->round->outstanding.erase(handle) && impl_->round->outstanding.empty() &&
        impl_->notify_depth == 0)
        impl_->advance();
    return Result::accepted;
}

Result IdentityManager::trigger() {
    if (!impl_->pool.next_valid(impl_->runtime.now())) return Result::rejected;
    impl_->pending_trigger = true;
    impl_->try_start();
    return Result::accepted;
}

LockHandle IdentityManager::lock(std::uint8_t duration_seconds) {
    const auto handle = impl_->next_lock++;
    impl_->locks[handle] = impl_->runtime.now() + std::chrono::seconds(duration_seconds);
    impl_->arm_lock_timer();
    if (duration_seconds == 0) impl_->on_lock_timer(); // released at once
    return handle;
}

Result IdentityManager::unlock(LockHandle handle) {
    if (impl_->locks.erase(handle) == 0) return Result::invalid_argument;
    impl_->arm_lock_timer();
    impl_->try_start();
    return Result::accepted;
}

Identifier IdentityManager::current_identifier() const { return impl_->current(); }
bool IdentityManager::change_pending() const { return static_cast<bool>(impl_->round); }
void IdentityManager::set_response_timeout(Clock::duration timeout) { impl_->response_timeout = timeout; }
void IdentityManager::on_committed(std::function<void(const Identifier&)> callback) { impl_->committed = std::move(callback); }
const IdentityManager::Statistics& IdentityManager::statistics() const { return impl_->stats; }
bool IdentityManager::locked() const { return impl_->locked(); }

} // namespace vanetza_idf::security
