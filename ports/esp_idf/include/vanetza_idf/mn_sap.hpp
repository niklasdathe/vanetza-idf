#pragma once
#include <vanetza_idf/stack.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/geonet/address.hpp>
#include <cstdint>
#include <optional>
#include <vector>

/** MN-SAP language binding: management entity <-> networking & transport layer.
 *
 * - TS 102 723-4 V1.1.1 clause 5: the MN-SAP provides MN-COMMAND and MN-REQUEST
 *   whose primitives are specified in TS 102 723-1 (not reproduced here; the
 *   generic envelope is the one of TS 102 723-3 Tables 1 to 4: id, CommandRef,
 *   command/request number and value, ErrStatus).
 * - TS 103 836-4-1 V2.2.1 Annex K: CORE_MMT.request/.response carry time, the
 *   local position vector, the GeoNetworking address and the TC mapping from
 *   the N&T management entity to the GN core; EN 302 890-2 V2.1.1 clause
 *   5.5.2 names the PoTi minimum data set (timestamp, latitude, longitude,
 *   horizontal confidence) a networking function receives.
 * - TS 103 175 V1.1.1 clause 8.3: MN-GET/MN-SET for the DCC N-Params of
 *   Table 10, served by the access/DCC adapter of the application.
 * The management entity may run in the same task or elsewhere; the library
 * only applies what it receives and forwards what it cannot answer itself.
 */
namespace vanetza_idf::MN_SAP {

/// TS 103 836-4-1 V2.2.1 clause K.2: CORE_MMT.request Request cause
enum class RequestCause : std::uint8_t { TIME, POSITION_VECTOR, GN_ADDRESS_INITIAL, GN_ADDRESS_DAD, TC_MAPPING };
struct CORE_MMT_request { RequestCause request_cause; };

/// Clause K.3: CORE_MMT.response, all parameters optional, at least one present
struct CORE_MMT_response {
    std::optional<vanetza::Clock::time_point> time;         // reference time for freshness of received packets
    std::optional<vanetza::PositionFix> local_position_vector; // position, speed, heading, timestamp, accuracy
    std::optional<vanetza::geonet::Address> geonetworking_address;
    std::optional<std::vector<std::uint8_t>> tc_mapping;    // Annex G traffic class parameters (opaque here)
};

/** Apply a CORE_MMT.response to the GN core. Time -> Stack::advance, position ->
 * Stack::update_position. The GeoNetworking address is accepted only with
 * itsGnLocalAddrConfMethod == Managed (clause 10.2.1.3.3: the GN core updates the
 * MID with an unsolicited CORE_MMT.response); with Auto (10.2.1.2: the address is
 * not changed) or Anonymous (10.2.1.4: the security entity owns the identifier) it
 * is refused with Result::unsupported. TC mapping is refused as unsupported: the
 * port uses the fixed TS 102 687 profile-to-access-category mapping. An empty
 * response is Result::invalid_argument; the first failing parameter stops. */
Result CORE_MMT_response_apply(Stack&, const CORE_MMT_response&);

/// TS 102 723-3 V1.1.1 Table 2 ErrStatus is "specified in TS 102 723-1"; that text is not
/// available to this library, so only the values named in TS 102 723-3 clause 5.2.3
/// (5 = INVALID COMMAND/REQUEST NUMBER) and this library's outcomes are enumerated.
enum class ErrStatus : std::uint8_t {
    SUCCESS = 0,
    INVALID_COMMAND_REQUEST_NUMBER = 5,
    UNSUPPORTED = 250,   // library: no provider for this parameter
    READ_ONLY = 251,     // library: TS 103 175 Table 10 access R
    INVALID_VALUE = 252, // library: outside the Table 10 format
    FAILED = 253         // library: provider reported a failure
};

/// TS 103 175 V1.1.1 Table 10: N-Param.No for the DCC interface at the MN-SAP
enum class N_Param_No : std::uint8_t {
    GLOBAL_CBR = 0,           // R, 1 octet 0..100 (TS 102 636-4-2 global CBR of the selected channel)
    CHANNEL_NUMBER = 1,       // R/W, 1 octet 1..7 (selects the channel for consecutive reads/writes)
    LOCAL_CBR = 2,            // R, 1 octet 0..100 (from the MI-SAP for the selected channel)
    AVAILABLE_RESOURCE = 3,   // R, 2 octets, reciprocal value of CBRa
    LAST_TRANSMIT_TIME = 4,   // R, 4 octets, granularity 1 OFDM symbol = 8 us
    IDLE_TIME = 5,            // R/W, 2 octets in ms (Toff per radio channel)
    TX_POWER_LEVEL_LIMIT = 6, // R/W, 1 octet, bits 0..4 EIRP 0..31 dBm, bits 5..7 reserved
};
struct N_Param { N_Param_No no; std::uint32_t value; };
struct N_Error { N_Param_No n_param_no; ErrStatus err_status; };

/// Table 6: MN-GET.request
struct MN_GET_request { std::uint32_t nt_id; std::uint8_t command_ref; std::vector<N_Param_No> n_param_no; };
/// Table 7: MN-GET.confirm
struct MN_GET_confirm { std::uint32_t nt_id; std::uint8_t command_ref; std::vector<N_Param> n_param; std::vector<N_Error> errors; };
/// Table 8: MN-SET.request
struct MN_SET_request { std::uint32_t nt_id; std::uint8_t command_ref; std::vector<N_Param> n_param; };
/// Table 9: MN-SET.confirm (Errors optional)
struct MN_SET_confirm { std::uint32_t nt_id; std::uint8_t command_ref; std::vector<N_Error> errors; };

/** Implemented by the access/DCC adapter of the application: the only source of
 * channel load, transmit times and power limits. The stack never invents these. */
class NetworkParameterProvider {
public:
    virtual ~NetworkParameterProvider() = default;
    virtual ErrStatus get(N_Param_No, std::uint32_t& value) = 0;
    virtual ErrStatus set(N_Param_No, std::uint32_t value) = 0;
};

/// Format limits of Table 10; a value outside is INVALID_VALUE before the provider sees it
bool n_param_value_in_format(N_Param_No, std::uint32_t value);
bool n_param_writable(N_Param_No);

/** MN-GET/MN-SET over a provider; a null provider answers UNSUPPORTED for every parameter. */
MN_GET_confirm MN_GET_request_submit(NetworkParameterProvider*, const MN_GET_request&);
MN_SET_confirm MN_SET_request_submit(NetworkParameterProvider*, const MN_SET_request&);

} // namespace vanetza_idf::MN_SAP
