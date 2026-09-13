#include <vanetza_idf/its_g5_frame.hpp>
#include <algorithm>

namespace vanetza_idf::its_g5 {
namespace {
constexpr std::uint8_t snap[] = {0xaa, 0xaa, 0x03, 0, 0, 0, 0x89, 0x47};
}
Result encode_frame(const AlDataRequest& request, std::uint16_t sequence, vanetza::ByteBuffer& out) {
    if (validate(request, maximum_gnpdu) != Result::accepted || sequence > 4095)
        return Result::invalid_argument;
    out.assign(34 + request.data.size(), 0);
    out[0] = 0x88; // QoS Data; To DS=From DS=0 (OCB), no encryption at MAC.
    std::copy(request.destination.octets.begin(), request.destination.octets.end(), out.begin() + 4);
    std::copy(request.source.octets.begin(), request.source.octets.end(), out.begin() + 10);
    std::fill(out.begin() + 16, out.begin() + 22, 0xff); // wildcard BSSID
    out[22] = (sequence << 4) & 0xff; out[23] = sequence >> 4;
    out[24] = request.priority; // TID carries IEEE 802.1D user priority.
    std::copy(std::begin(snap), std::end(snap), out.begin() + 26);
    std::copy(request.data.begin(), request.data.end(), out.begin() + 34);
    return Result::accepted;
}
Result decode_frame(const std::uint8_t* data, std::size_t length, bool fcs, AlDataIndication& out) {
    if (!data || length < 34 + (fcs ? 4u : 0u)) return Result::invalid_argument;
    if (fcs) length -= 4;
    // Only non-fragmented, unprotected QoS Data with the OCB three-address
    // layout. Reject A-MSDU/HT-control rather than misinterpreting their offsets.
    if (data[0] != 0x88 || (data[1] & 0xc7) || (data[22] & 0x0f) ||
        (data[24] & 0x80) || !std::all_of(data + 16, data + 22, [](auto b) { return b == 0xff; }))
        return Result::unsupported;
    if (!std::equal(std::begin(snap), std::end(snap), data + 26)) return Result::unsupported;
    if (length == 34 || length - 34 > maximum_gnpdu) return Result::invalid_argument;
    std::copy(data + 4, data + 10, out.destination.octets.begin());
    std::copy(data + 10, data + 16, out.source.octets.begin());
    out.data.assign(data + 34, data + length);
    return Result::accepted;
}
}
