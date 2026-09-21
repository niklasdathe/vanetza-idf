#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/net/mac_address.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#if VIDF_NETWORK
#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/channel_load.hpp>
#endif

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

/** Access profile has no BTP/GN state and preserves the AL_DATA parameters.
 *
 * On a VIDF_NETWORK build, optionally runs DCC_ACC (TS 102 687 V1.2.1 clause 5.4 Adaptive
 * approach, gated by the Annex B budget/gate-keeper) in front of the backend, per
 * SYS-DCC-001/GAP-DCC-001. Disabled by default so existing callers (host tests, other
 * applications) are unaffected; the ESP32-C5 firmware enables it once it has a real CBR
 * source (SYS-DCC-002). The DCC methods below do not exist on an access-only build (no
 * VIDF_NETWORK): the Adaptive approach lives in vanetza/dcc, which that configuration does
 * not compile, matching the documented access-only deployment (docs/idf/conformance.md).
 */
class AccessStack {
public:
    explicit AccessStack(Access& access, std::size_t maximum_gnpdu = 4096);
    ~AccessStack();
    AccessStack(const AccessStack&) = delete;
    AccessStack& operator=(const AccessStack&) = delete;

#if VIDF_NETWORK
    /** Enable the Adaptive DCC_ACC gate. cbr_target defaults to TS 103 836-4-2's
     * itsGNCBRTarget = 0.62, the value the project's SYS-DCC-001/002/003 use consistently
     * (not TS 102 687 Table 3's older, superseded 0.68 default).
     * runtime must outlive this AccessStack and must be the same Runtime driving the caller's
     * periodic advance()/trigger() (e.g. the Stack's ManualRuntime), since the Adaptive approach
     * reschedules itself every 200 ms of that runtime's own clock.
     * Call once, before the first request().
     */
    void enable_dcc(vanetza::Runtime& runtime, vanetza::dcc::ChannelLoad cbr_target = vanetza::dcc::ChannelLoad(0.62));

    /** Feed the latest channel-busy-ratio measurement at roughly the T_Cbr cadence (100 ms):
     * local LCBR (SYS-DCC-002), or CBR_G when a Release-2 DCC_NET has one available
     * (SYS-DCC-001: "consume Release-2 CBR_G when available, otherwise LCBR"). No-op unless
     * enable_dcc was called.
     */
    void report_channel_load(vanetza::dcc::ChannelLoad);

    /** Permitted duty cycle (delta) from the last periodic Adaptive-approach update.
     * Returns UnitInterval(1.0) (unrestricted) when DCC is not enabled.
     */
    vanetza::UnitInterval permitted_duty_cycle() const;
#endif

    Result request(AlDataRequest);
private:
#if VIDF_NETWORK
    class Dcc;
    std::unique_ptr<Dcc> dcc_;
#endif
    Access& access_;
    std::size_t maximum_gnpdu_;
};
}
