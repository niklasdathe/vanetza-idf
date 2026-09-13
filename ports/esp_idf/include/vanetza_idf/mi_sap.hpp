#pragma once
#include <vanetza_idf/mn_sap.hpp>
#include <cstdint>
#include <vector>

/** MI-SAP language binding: management entity <-> access layer, DCC subset.
 *
 * - TS 102 723-3 V1.1.1 clauses 7 and 8: MI-SET.request/.confirm (Tables 5/6)
 *   and MI-GET.request/.confirm (Tables 7/8) with MAC-ID, CommandRef and a
 *   sequence of I-Param; clause 5.2.3: an undefined command is acknowledged
 *   with ErrStatus 5 "INVALID COMMAND/REQUEST NUMBER".
 * - TS 103 175 V1.1.1 clause 8.2: the DCC I-Params of Table 5 (clauses 6.2 and
 *   6.3 DCC_CROSS_Access).
 * Binding only: the access adapter of the application may implement
 * AccessParameterProvider; the library reads channel load and transmit
 * timing from nowhere else and invents no values.
 */
namespace vanetza_idf::MI_SAP {

using MN_SAP::ErrStatus;

/// TS 103 175 V1.1.1 Table 5: I-Param.No for the DCC interface at the MI-SAP
enum class I_Param_No : std::uint8_t {
    CHANNEL_NUMBER = 52,       // R/W, 1 octet 1..7
    LOCAL_CBR = 53,            // R, 1 octet 0..100 (CL measurement of TS 102 687)
    MESSAGE_LENGTH = 54,       // R, 1 octet, granularity 1 OFDM symbol = 8 us (air time Ton)
    LAST_TRANSMIT_TIME = 55,   // R, 4 octets, granularity 1 OFDM symbol = 8 us
    IDLE_TIME = 56,            // R/W, 2 octets in ms (Toff)
    TX_POWER_LEVEL_LIMIT = 57, // R/W, 1 octet, bits 0..4 EIRP 0..31 dBm, bits 5..7 reserved
};
struct I_Param { I_Param_No no; std::uint32_t value; };
struct I_Error { I_Param_No i_param_no; ErrStatus err_status; };

/// TS 102 723-3 Table 7 / TS 103 175 Table 1: MI-GET.request (MAC-ID structure of TS 102 723-1 reduced to an id)
struct MI_GET_request { std::uint32_t mac_id; std::uint8_t command_ref; std::vector<I_Param_No> i_param_no; };
/// TS 102 723-3 Table 8 / TS 103 175 Table 2: MI-GET.confirm
struct MI_GET_confirm { std::uint32_t mac_id; std::uint8_t command_ref; std::vector<I_Param> i_param; std::vector<I_Error> errors; };
/// TS 102 723-3 Table 5 / TS 103 175 Table 3: MI-SET.request
struct MI_SET_request { std::uint32_t mac_id; std::uint8_t command_ref; std::vector<I_Param> i_param; };
/// TS 102 723-3 Table 6 / TS 103 175 Table 4: MI-SET.confirm (Errors optional)
struct MI_SET_confirm { std::uint32_t mac_id; std::uint8_t command_ref; std::vector<I_Error> errors; };

class AccessParameterProvider {
public:
    virtual ~AccessParameterProvider() = default;
    virtual ErrStatus get(I_Param_No, std::uint32_t& value) = 0;
    virtual ErrStatus set(I_Param_No, std::uint32_t value) = 0;
};

bool i_param_value_in_format(I_Param_No, std::uint32_t value);
bool i_param_writable(I_Param_No);

MI_GET_confirm MI_GET_request_submit(AccessParameterProvider*, const MI_GET_request&);
MI_SET_confirm MI_SET_request_submit(AccessParameterProvider*, const MI_SET_request&);

} // namespace vanetza_idf::MI_SAP
