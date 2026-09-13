#include <vanetza_idf/hil.hpp>
#include <algorithm>
#include <stdexcept>

namespace vanetza_idf::hil {
namespace {
constexpr std::uint8_t magic[] = {'V','I','D','1'};
std::uint32_t crc32(const std::uint8_t* data, std::size_t size) {
    std::uint32_t crc = 0xffffffff;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
void append32(vanetza::ByteBuffer& b, std::uint32_t n) {
    for (int shift = 24; shift >= 0; shift -= 8) b.push_back(n >> shift);
}
std::uint32_t read32(const std::uint8_t* p) {
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3];
}
}
vanetza::ByteBuffer encode(const Frame& frame, std::size_t maximum) {
    const auto size = frame.payload.size();
    const auto channel = static_cast<unsigned>(frame.channel);
    if (maximum > 65535 || size == 0 || size > maximum || channel < 1 || channel > 3)
        throw std::invalid_argument("Invalid HIL frame");
    vanetza::ByteBuffer b(std::begin(magic), std::end(magic));
    b.push_back(channel);
    append32(b, frame.sequence);
    b.push_back(size >> 8); b.push_back(size);
    b.insert(b.end(), frame.payload.begin(), frame.payload.end());
    append32(b, crc32(b.data(), b.size()));
    return b;
}
Decoder::Decoder(std::size_t maximum) : maximum_(maximum) {
    if (maximum == 0 || maximum > 65535) throw std::invalid_argument("Invalid HIL MTU");
    buffer_.reserve(maximum + 15);
}
void Decoder::feed(const std::uint8_t* p, std::size_t size, const Handler& handler) {
    if (!p && size) throw std::invalid_argument("Null HIL bytes");
    // At most MTU+15 bytes retained regardless of input chunk size.
    for (std::size_t i = 0; i < size; ++i) { buffer_.push_back(p[i]); process(handler); }
}
void Decoder::process(const Handler& handler) {
    while (buffer_.size() >= 4) {
        if (!std::equal(std::begin(magic), std::end(magic), buffer_.begin())) {
            buffer_.erase(buffer_.begin()); continue;
        }
        if (buffer_.size() < 11) return;
        const auto size = (std::size_t(buffer_[9]) << 8) | buffer_[10];
        if (buffer_[4] < 1 || buffer_[4] > 3 || size == 0 || size > maximum_) {
            buffer_.erase(buffer_.begin()); continue;
        }
        const auto total = size + 15;
        if (buffer_.size() < total) return;
        if (crc32(buffer_.data(), total - 4) != read32(buffer_.data() + total - 4)) {
            buffer_.erase(buffer_.begin()); continue;
        }
        Frame frame {static_cast<Channel>(buffer_[4]), read32(buffer_.data() + 5),
                     {buffer_.begin() + 11, buffer_.begin() + 11 + size}};
        buffer_.erase(buffer_.begin(), buffer_.begin() + total);
        handler(std::move(frame));
    }
}
}
