#include "hil_sut.hpp"
#include <vanetza_idf/nf_sap.hpp>
#include <algorithm>

namespace vidf_test {
using namespace vanetza_idf;
using vanetza::ByteBuffer;
namespace {
void u16(ByteBuffer& out, std::size_t n) { out.push_back(n >> 8); out.push_back(n); }
std::uint16_t read16(const ByteBuffer& in, std::size_t n) { return (in[n] << 8) | in[n + 1]; }
}
void Sut::record(std::uint8_t kind, ByteBuffer bytes) {
    if (record_bytes_ + bytes.size() + 3 > 3800 || records_.size() >= 32) { overflow_ = true; return; }
    ByteBuffer frame {kind}; u16(frame, bytes.size());
    frame.insert(frame.end(), bytes.begin(), bytes.end());
    record_bytes_ += frame.size(); records_.push_back(std::move(frame));
}
Result Sut::request(AlDataRequest request) {
    record(1, std::move(request.data));
    return overflow_ ? Result::resource_limit : Result::accepted;
}
Result Sut::reset() {
    stack_.reset(); // Router timer cancellation precedes runtime destruction.
    runtime_ = std::make_unique<vanetza::ManualRuntime>();
    StackConfig config;
    config.mib.itsGnSecurity = false; // explicit unsecured BTP test PICS
    config.mib.vanetzaDisableBeaconing = true;
    config.mib.itsGnLocalGnAddr.mid({2, 0, 0, 0, 0, 1});
    stack_ = std::make_unique<Stack>(config, *runtime_, *this);
    stack_->on_receive([this](BtpIndication received) {
        auto indication = NF_SAP::BTP_DATA_indication_from(std::move(received));
        ByteBuffer data {static_cast<std::uint8_t>(indication.btp_type == BtpType::b)};
        u16(data, indication.destination_port);
        u16(data, indication.source_port.value_or(indication.destination_port_info.value_or(0)));
        data.insert(data.end(), indication.received_fl_sdu.begin(), indication.received_fl_sdu.end());
        record(2, std::move(data));
    });
    stack_->on_receive_gn([this](GnIndication received) {
        // GN-DATA.indication with no registered upper protocol (raw test SDU).
        record(3, std::move(received.data));
    });
    vanetza::PositionFix fix {};
    fix.latitude = 52.0 * vanetza::units::degree;
    fix.longitude = 13.0 * vanetza::units::degree;
    fix.speed = 0.0 * vanetza::units::si::meters_per_second;
    fix.course = 0.0 * vanetza::units::true_north_degrees;
    return stack_->update_position(fix);
}
ByteBuffer Sut::execute(const ByteBuffer& input) {
    records_.clear(); record_bytes_ = 0; overflow_ = false;
    Result result = Result::invalid_argument;
    try {
        if (input.size() == 1 && input[0] == 0) result = reset();
        else if (!stack_) result = Result::rejected;
        else if (input.size() >= 6 && input[0] == 1 && input[1] <= 1) {
            NF_SAP::BTP_DATA_request request;
            request.btp_type = input[1] ? BtpType::b : BtpType::a;
            request.destination_port = read16(input, 2);
            if (request.btp_type == BtpType::a) request.source_port = read16(input, 4);
            else request.destination_port_info = read16(input, 4);
            request.fl_sdu.assign(input.begin() + 6, input.end());
            request.length = request.fl_sdu.size();
            result = NF_SAP::BTP_DATA_request_submit(*stack_, std::move(request));
        } else if (input.size() > 13 && input[0] == 2) {
            AlDataIndication indication;
            std::copy(input.begin() + 1, input.begin() + 7, indication.source.octets.begin());
            std::copy(input.begin() + 7, input.begin() + 13, indication.destination.octets.begin());
            indication.data.assign(input.begin() + 13, input.end());
            result = stack_->indicate(std::move(indication));
        } else if (input.size() >= 2 && input[0] == 3) {
            // GN-DATA.request, SHB only (GAP-GN-001): [3][raw traffic class][payload].
            GnRequest request;
            request.traffic_class = vanetza::geonet::TrafficClass(input[1]);
            request.data.assign(input.begin() + 2, input.end());
            result = stack_->request(std::move(request));
        } else if (input.size() == 9 && input[0] == 4) {
            // UtGnChangePosition-style fix: [4][lat i32 BE][lon i32 BE], 1e-7 degree units.
            const auto i32 = [&](std::size_t at) {
                return static_cast<std::int32_t>((std::uint32_t(input[at]) << 24) | (std::uint32_t(input[at + 1]) << 16) |
                                                  (std::uint32_t(input[at + 2]) << 8) | input[at + 3]);
            };
            vanetza::PositionFix fix {};
            fix.latitude = (i32(1) / 1.0e7) * vanetza::units::degree;
            fix.longitude = (i32(5) / 1.0e7) * vanetza::units::degree;
            fix.speed = 0.0 * vanetza::units::si::meters_per_second;
            fix.course = 0.0 * vanetza::units::true_north_degrees;
            result = stack_->update_position(fix);
        } else if (!input.empty() && input[0] > 4) result = Result::unsupported;
    } catch (const std::bad_alloc&) { result = Result::resource_limit; }
      catch (const std::exception&) { result = Result::rejected; }
    if (overflow_) result = Result::resource_limit;
    ByteBuffer output {static_cast<std::uint8_t>(result), static_cast<std::uint8_t>(records_.size())};
    for (const auto& record : records_) output.insert(output.end(), record.begin(), record.end());
    return output;
}
}
