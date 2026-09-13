#pragma once
#include <vanetza_idf/access.hpp>

namespace vanetza_idf::its_g5 {
// IEEE 802.11 QoS Data header (26 octets) and IEEE 802 LLC/SNAP (8 octets).
// EN 303 797 clauses 4.4/4.5 and Annex B.2; GeoNetworking EtherType 0x8947.
constexpr std::size_t maximum_gnpdu = 2296;
Result encode_frame(const AlDataRequest&, std::uint16_t sequence, vanetza::ByteBuffer&);
// Caller declares FCS presence; this function never guesses from payload bytes.
// Receive PHY/FCS status must be checked by the radio before calling this:
// on ESP32-C5, any frame reaching the promiscuous callback has already passed
// a real hardware FCS check (WIFI_PROMIS_FILTER_MASK_FCSFAIL is never set),
// and the 4 trailing bytes this flag strips are not a software-recoverable
// copy of that FCS -- see c5_radio.cpp's receive() for the measured evidence.
Result decode_frame(const std::uint8_t*, std::size_t, bool includes_fcs, AlDataIndication&);
}
