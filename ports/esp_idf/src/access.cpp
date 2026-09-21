#include <vanetza_idf/access.hpp>
#include <cmath>
#include <utility>
#if VIDF_NETWORK
#include <vanetza/access/data_rates.hpp>
#include <vanetza/dcc/limeric.hpp>
#include <vanetza/dcc/limeric_budget.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/dcc/transmission.hpp>
#include <array>
#include <chrono>
#endif

namespace vanetza_idf {
Result validate(const AlDataRequest& request, std::size_t maximum) {
    if (request.data.empty() || request.data.size() > maximum || request.priority > 7 ||
        !std::isfinite(request.transmit_power_dbm) || request.bandwidth_mhz == 0)
        return Result::invalid_argument;
    return Result::accepted;
}
#if VIDF_NETWORK
namespace {
// EN 303 797 V2.1.1 clause 4.6.2's Ton limit (SYS-DCC-001 acceptance criterion 3); a single
// frame at or below this duration also cannot alone exceed the 3 % duty cycle at Toff>=25 ms.
constexpr vanetza::Clock::duration max_ton = std::chrono::milliseconds(4);
// Index by OfdmMcs; mirrors the rate table in C5Radio::request/transmit_burst.
constexpr std::array<const vanetza::access::DataRateG5*, 8> g5_rates {
    &vanetza::access::G5_3Mbps, &vanetza::access::G5_4dot5Mbps, &vanetza::access::G5_6Mbps,
    &vanetza::access::G5_9Mbps, &vanetza::access::G5_12Mbps, &vanetza::access::G5_18bps,
    &vanetza::access::G5_24Mbps, &vanetza::access::G5_27Mbps,
};
// Airtime-only use of Transmission::channel_occupancy(); profile is immaterial here since no
// FlowControl queueing is involved, only the data-rate/length formula.
vanetza::Clock::duration request_airtime(const AlDataRequest& request) {
    vanetza::dcc::TransmissionLite transmission(vanetza::dcc::Profile::DP2, request.data.size());
    const auto index = static_cast<unsigned>(request.mcs);
    transmission.m_data_rate = index < g5_rates.size() ? g5_rates[index] : nullptr;
    return transmission.channel_occupancy();
}
// TS 102 687 V1.2.1 Table 3 defaults, with cbr_target overridden to the project's Release-2
// value (SYS-DCC-001/002/003; see AccessStack::enable_dcc's docstring for why).
vanetza::dcc::Limeric::Parameters limeric_parameters(vanetza::dcc::ChannelLoad cbr_target) {
    vanetza::dcc::Limeric::Parameters parameters;
    parameters.cbr_target = cbr_target;
    return parameters;
}
} // namespace

class AccessStack::Dcc {
public:
    Dcc(vanetza::Runtime& rt, vanetza::dcc::ChannelLoad target) :
        limeric(rt, limeric_parameters(target)),
        budget(limeric, rt)
    {
        // TS 102 687 V1.2.1 Annex B: the gate-opening time depends on the current permitted
        // duty cycle, so it must be recalculated whenever the Adaptive approach updates delta.
        limeric.on_duty_cycle_change = [this](const vanetza::dcc::Limeric*, vanetza::Clock::time_point) {
            budget.update();
        };
    }
    vanetza::dcc::Limeric limeric;
    vanetza::dcc::LimericBudget budget;
};

void AccessStack::enable_dcc(vanetza::Runtime& runtime, vanetza::dcc::ChannelLoad cbr_target) {
    dcc_ = std::make_unique<Dcc>(runtime, cbr_target);
}

void AccessStack::report_channel_load(vanetza::dcc::ChannelLoad load) {
    if (dcc_) dcc_->limeric.update_cbr(load);
}

vanetza::UnitInterval AccessStack::permitted_duty_cycle() const {
    return dcc_ ? dcc_->limeric.permitted_duty_cycle() : vanetza::UnitInterval(1.0);
}
#endif

AccessStack::AccessStack(Access& access, std::size_t maximum) :
    access_(access), maximum_gnpdu_(maximum) {}
AccessStack::~AccessStack() = default;

Result AccessStack::request(AlDataRequest request) {
    auto result = validate(request, maximum_gnpdu_);
    if (result != Result::accepted) return result;
#if VIDF_NETWORK
    if (dcc_) {
        const auto ton = request_airtime(request);
        if (ton <= vanetza::Clock::duration::zero() || ton > max_ton) return Result::invalid_argument;
        if (dcc_->budget.delay() > vanetza::Clock::duration::zero()) return Result::resource_limit;
        result = access_.request(std::move(request));
        if (result == Result::accepted) dcc_->budget.notify(ton);
        return result;
    }
#endif
    return access_.request(std::move(request));
}
}
