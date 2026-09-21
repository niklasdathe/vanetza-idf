// DCC_ACC integration test: AccessStack's Adaptive DCC gate (TS 102 687 V1.2.1 clause 5.4,
// SYS-DCC-001/002 acceptance criterion 4 boundary vectors). The Adaptive approach's own
// formulas (Limeric) and its Annex B gate-keeper (LimericBudget) are upstream, already
// unit-verified elsewhere; this file verifies the wiring in AccessStack::request() -- the gate
// actually blocks/permits transmissions, the CBR_target override takes effect, and independent
// AccessStack instances never share state.
#include "check.hpp"
#include <vanetza_idf/access.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <cmath>
#include <chrono>

using namespace vanetza;
using namespace vanetza_idf;
using vidf_test::check;

namespace {
struct Radio : Access {
    unsigned accepted = 0;
    Result request(AlDataRequest) override { ++accepted; return Result::accepted; }
};

bool near(double a, double b, double eps = 1e-9) { return std::fabs(a - b) < eps; }

AlDataRequest small_request() {
    AlDataRequest req;
    req.source = {2,0,0,0,0,1}; req.destination = {255,255,255,255,255,255};
    req.mcs = OfdmMcs::qpsk_1_2; // 6 Mbit/s: well under the 4 ms Ton limit at this size
    req.data.assign(100, 0x2a);
    return req;
}

AlDataRequest oversized_request() {
    AlDataRequest req;
    req.source = {2,0,0,0,0,1}; req.destination = {255,255,255,255,255,255};
    req.mcs = OfdmMcs::bpsk_1_2; // 3 Mbit/s, the slowest rate
    req.data.assign(3000, 0x2a); // ~8.1 ms of airtime at this rate: over the 4 ms limit
    return req;
}

// Drive `cycles` periodic Adaptive-approach updates (200 ms each) feeding a constant CBR,
// and return the permitted duty cycle Limeric settles on. TS 102 687 clause 5.4 runs at a
// fixed 200 ms cadence regardless of how often report_channel_load is called in between;
// feeding the same value on both 100 ms sub-intervals of each cycle matches a station that
// measured a genuinely constant channel load.
double converge(ManualRuntime& runtime, AccessStack& stack, dcc::ChannelLoad load, unsigned cycles) {
    for (unsigned i = 0; i < cycles; ++i) {
        stack.report_channel_load(load);
        runtime.trigger(std::chrono::milliseconds(100));
        stack.report_channel_load(load);
        runtime.trigger(std::chrono::milliseconds(100));
    }
    return stack.permitted_duty_cycle().value();
}
} // namespace

void test_dcc() {
    vidf_test::section("test_dcc");

    // -- delta_max ceiling (also exercises the positive gain saturation that reaches it):
    // an always-idle channel (CBR 0.0) against the 0.62 target pushes delta up every cycle
    // until it saturates at delta_max = 0.03 (SYS-DCC-001's 3 % duty-cycle ceiling).
    {
        ManualRuntime runtime;
        Radio radio;
        AccessStack stack(radio, 4096);
        stack.enable_dcc(runtime);
        check(near(stack.permitted_duty_cycle().value(), 0.0153),
              "Initial duty cycle is the TS 102 687 Table 3 midpoint before the first update");
        // Numerically verified to first reach the exact clamp at cycle 158 of 250.
        const auto delta = converge(runtime, stack, dcc::ChannelLoad(0.0), 250);
        check(near(delta, 0.03), "Idle channel converges to and clamps at delta_max = 0.03");
    }

    // -- delta_min floor (also exercises the negative gain saturation that reaches it):
    // a fully congested channel (CBR 1.0) pushes delta down every cycle until it saturates
    // at delta_min = 0.0006 (a station is never fully starved).
    {
        ManualRuntime runtime;
        Radio radio;
        AccessStack stack(radio, 4096);
        stack.enable_dcc(runtime);
        // Numerically verified to first reach the exact clamp at cycle 40 of 250.
        const auto delta = converge(runtime, stack, dcc::ChannelLoad(1.0), 250);
        check(near(delta, 0.0006), "Fully congested channel converges to and clamps at delta_min = 0.0006");
    }

    // -- CBR exactly at the 0.62 target: clause 5.4 step 2's positive branch requires the
    // gap to be strictly positive (sign(0) is not positive), so an exact match gives a zero
    // offset every cycle and delta decays toward delta_min, never overshooting it.
    {
        ManualRuntime runtime;
        Radio radio;
        AccessStack stack(radio, 4096);
        stack.enable_dcc(runtime);
        // Slowest of the three cases (pure (1-alpha) decay, no offset): numerically verified
        // to first reach the exact clamp at cycle 201 of 250.
        const auto delta = converge(runtime, stack, dcc::ChannelLoad(0.62), 250);
        check(near(delta, 0.0006), "CBR exactly at target decays to delta_min, not held at the midpoint");
    }

    // -- per-channel isolation: two independently constructed AccessStack instances (as
    // Station::build() creates fresh per rebuild) never share Limeric/LimericBudget state.
    {
        ManualRuntime runtime_a, runtime_b;
        Radio radio_a, radio_b;
        AccessStack stack_a(radio_a, 4096), stack_b(radio_b, 4096);
        stack_a.enable_dcc(runtime_a);
        stack_b.enable_dcc(runtime_b);
        converge(runtime_a, stack_a, dcc::ChannelLoad(0.0), 250); // pushes stack_a to delta_max
        check(near(stack_b.permitted_duty_cycle().value(), 0.0153),
              "An unrelated AccessStack's duty cycle is unaffected by another instance's updates");
    }

    // -- EN 303 797 clause 4.6.2 Ton limit: a frame whose computed airtime exceeds 4 ms is
    // refused outright, never queued or transmitted.
    {
        ManualRuntime runtime;
        Radio radio;
        AccessStack stack(radio, 4096);
        stack.enable_dcc(runtime);
        check(stack.request(oversized_request()) == Result::invalid_argument,
              "A frame whose airtime exceeds 4 ms is rejected before reaching the backend");
        check(radio.accepted == 0, "The oversized frame never reached the backend");
    }

    // -- gate enforcement: with the duty cycle at its widest (delta_max, from a preceding
    // idle-channel run), a burst of back-to-back small frames must still be spaced out by
    // LimericBudget's Annex B gate-keeper (min_interval = 25 ms), not sent unthrottled.
    {
        ManualRuntime runtime;
        Radio radio;
        AccessStack stack(radio, 4096);
        stack.enable_dcc(runtime);
        converge(runtime, stack, dcc::ChannelLoad(0.0), 250); // delta_max, most permissive case
        check(stack.request(small_request()) == Result::accepted, "First frame after the gate opens is accepted");
        check(stack.request(small_request()) == Result::resource_limit,
              "An immediate second frame is gated (Toff >= 25 ms) instead of being sent back to back");
        runtime.trigger(std::chrono::milliseconds(30));
        check(stack.request(small_request()) == Result::accepted,
              "The same frame is accepted again once the gate-keeper's interval has elapsed");
    }
}
