#pragma once
#include <vanetza_idf/access.hpp>
#include <functional>
#include <optional>

namespace vanetza_idf::hil {
/** Project test transport, NOT an ETSI on-air protocol or TTCN verdict.
 * VID1 | channel:u8 | sequence:u32be | length:u16be | payload | CRC32:u32be.
 * Payload on upper channel is unchanged ETSI adapter UT codec data.
 * Wire decoding is bounded and tolerates fragmentation and corrupt frames.
 */
enum class Channel : std::uint8_t { upper = 1, lower = 2, diagnostic = 3 };
struct Frame { Channel channel; std::uint32_t sequence; vanetza::ByteBuffer payload; };
vanetza::ByteBuffer encode(const Frame&, std::size_t maximum = 4096);
class Decoder {
public:
    using Handler = std::function<void(Frame)>;
    explicit Decoder(std::size_t maximum = 4096);
    void feed(const std::uint8_t*, std::size_t, const Handler&);
    std::size_t buffered() const { return buffer_.size(); }
private:
    std::size_t maximum_;
    vanetza::ByteBuffer buffer_;
    void process(const Handler&);
};

/** Actual SUT hooks: unknown/unimplemented commands have no successful reply.
 * A handler may return no response for unsupported commands; the TTCN testcase
 * then times out or receives its specified negative result from the handler.
 * No ACK is fabricated by the framing/transport code.
 */
using UpperTester = std::function<std::optional<vanetza::ByteBuffer>(const vanetza::ByteBuffer&)>;
}
