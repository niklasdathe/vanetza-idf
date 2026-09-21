#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/net/mac_address.hpp>
#include <cstdint>
#include <optional>

namespace vanetza_idf {

// Implementation result, NOT an additional ETSI AL-DATA.confirm primitive.
enum class Result { accepted, invalid_argument, unsupported, wrong_entry_point,
                    security_unavailable, resource_limit, rejected, time_regression,
                    identity_change_pending /*< TS 102 723-8 clause 6.3.1.3: between PREPARE and COMMIT */ };

// Named PHY modes avoid confusing legacy OFDM coding schemes with the SDK's
// rate indices or HT/NGV MCS indices. EN 303 797 clauses 4.3.1 and 4.3.2.
enum class OfdmMcs : std::uint8_t {
    bpsk_1_2, bpsk_3_4, qpsk_1_2, qpsk_3_4,
    qam16_1_2, qam16_3_4, qam64_2_3, qam64_3_4
};

/** Technology-specific AL_DATA.request: EN 303 797 V2.1.1, Annex B.2.
 * See docs/idf/standards.md (IF-IN-001). This is the AL_DATA binding,
 * not the separate IN-UNITDATA interface of TS 102 723-10.
 * This C++ binding is local: the standard does not prescribe a C++/BLE ABI.
 * Owns the GNPDU bytes; they exclude LLC, MAC and PHY headers.
 */
struct AlDataRequest {
    vanetza::MacAddress source;
    vanetza::MacAddress destination;
    std::uint8_t priority = 0; // IEEE 802.1D user priority 0..7, not EDCA ordinal
    double transmit_power_dbm = 0.0;
    OfdmMcs mcs = OfdmMcs::qpsk_1_2; // 6 Mbit/s at 10 MHz
    std::uint16_t bandwidth_mhz = 10;
    std::uint16_t channel_number = 180;
    std::uint8_t transceiver_id = 0;
    std::optional<std::uint8_t> transceiver_mode;
    std::optional<std::uint32_t> datastream_id;
    // DCC profile assigned by GeoNetworking's dcc::RequestInterface::request() (TS 102 687).
    // That call site performs no DCC enforcement itself (see stack.cpp); this field only carries
    // the profile through to the Access adapter, which is where enforcement belongs. Requests
    // built outside that path (e.g. the software lower tester's test_gn_request) keep the default.
    vanetza::dcc::Profile dcc_profile = vanetza::dcc::Profile::DP2;
    vanetza::ByteBuffer data;
};

/** AL_DATA.indication, EN 303 797 V2.1.1 Annex B.2 (IF-IN-002).
 * Optional radio measurements are absent when the backend cannot measure them;
 * zero must never stand for a made-up measurement.
 */
struct AlDataIndication {
    vanetza::MacAddress source;
    vanetza::MacAddress destination;
    std::optional<double> channel_busy_ratio;
    std::optional<double> received_power_dbm;
    std::uint16_t channel_number = 180;
    std::uint8_t receiver_id = 0;
    std::optional<std::uint8_t> receiver_mode;
    vanetza::ByteBuffer data;
};

/** Device-independent access adapter. Backend must reject unsupported controls,
 * apply DCC when allocated to access, and report reception via Stack::indicate.
 * request takes ownership even on failure. No callback from an interrupt.
 */
class Access {
public:
    virtual Result request(AlDataRequest) = 0;
    virtual ~Access() = default;
};

Result validate(const AlDataRequest&, std::size_t maximum_gnpdu);

/** Access profile has no BTP/GN state and preserves the AL_DATA parameters. */
class AccessStack {
public:
    explicit AccessStack(Access& access, std::size_t maximum_gnpdu = 4096);
    Result request(AlDataRequest);
private:
    Access& access_;
    std::size_t maximum_gnpdu_;
};
}
