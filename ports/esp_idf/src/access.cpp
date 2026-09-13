#include <vanetza_idf/access.hpp>
#include <utility>
#include <cmath>

namespace vanetza_idf {
Result validate(const AlDataRequest& request, std::size_t maximum) {
    if (request.data.empty() || request.data.size() > maximum || request.priority > 7 ||
        !std::isfinite(request.transmit_power_dbm) || request.bandwidth_mhz == 0)
        return Result::invalid_argument;
    return Result::accepted;
}
AccessStack::AccessStack(Access& access, std::size_t maximum) :
    access_(access), maximum_gnpdu_(maximum) {}
Result AccessStack::request(AlDataRequest request) {
    const auto result = validate(request, maximum_gnpdu_);
    return result == Result::accepted ? access_.request(std::move(request)) : result;
}
}
