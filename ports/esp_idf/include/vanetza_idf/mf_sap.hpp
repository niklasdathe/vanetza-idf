#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza_idf/mn_sap.hpp>
#include <cstdint>
#include <vector>

/** MF-SAP language binding: management entity -> facilities layer.
 *
 * - TS 102 723-5 V2.0.0 clause 5 incorporates V1.1.1 altogether, which (like
 *   TS 102 723-4 for MN) provides MF-COMMAND and MF-REQUEST with the generic
 *   envelope of TS 102 723-1: entity identifier, CommandRef, command/request
 *   number and value, ErrStatus in the confirm.
 * - TS 103 175 V1.1.1 clause 8.4: MF-SET.request/.confirm (Tables 11/12) with
 *   the DCC F-Params of Table 13, i.e. the channel-load feedback the DCC
 *   management entity gives the facilities layer (clause 6.5 DCC_CROSS_Facilities).
 * The facilities layer implements FacilitiesParameterSink; it may live in
 * another task, process or device, the library defines no transport.
 */
namespace vanetza_idf::MF_SAP {

using MN_SAP::ErrStatus;

/// TS 103 175 V1.1.1 Table 13: F-Param.No for the DCC interface at the MF-SAP
enum class F_Param_No : std::uint8_t {
    CHANNEL_NUMBER = 0,     // R/W, 1 octet 1..7 (selects the channel for consecutive reads/writes)
    AVAILABLE_RESOURCE = 1, // R/W, 2 octets, reciprocal value of CBRa on the selected channel
};
struct F_Param { F_Param_No no; std::uint32_t value; };
struct F_Error { F_Param_No f_param_no; ErrStatus err_status; };

/// Table 11: MF-SET.request
struct MF_SET_request { std::uint32_t fac_id; std::uint8_t command_ref; std::vector<F_Param> f_param; };
/// Table 12: MF-SET.confirm (Errors optional)
struct MF_SET_confirm { std::uint32_t fac_id; std::uint8_t command_ref; std::vector<F_Error> errors; };

/// TS 102 723-1 envelope (through TS 102 723-5): MF-COMMAND.request/.confirm, MF-REQUEST.request/.confirm.
/// Command and request numbers are entity specific (annexes of the respective part); opaque here.
struct MF_COMMAND_request { std::uint32_t fac_id; std::uint8_t command_ref; std::uint32_t command_no; vanetza::ByteBuffer value; };
struct MF_COMMAND_confirm { std::uint32_t fac_id; std::uint8_t command_ref; ErrStatus err_status; };
struct MF_REQUEST_request { std::uint32_t fac_id; std::uint8_t command_ref; std::uint32_t request_no; vanetza::ByteBuffer value; };
struct MF_REQUEST_confirm { std::uint32_t fac_id; std::uint8_t command_ref; ErrStatus err_status; vanetza::ByteBuffer value; };

/** Implemented by the facilities layer (e.g. the message generation services that
 * adapt their rate to the available resource). */
class FacilitiesParameterSink {
public:
    virtual ~FacilitiesParameterSink() = default;
    virtual ErrStatus set(F_Param_No, std::uint32_t value) = 0;
    /// MF-COMMAND / MF-REQUEST are delivered unchanged; a sink that knows no such number
    /// answers INVALID_COMMAND_REQUEST_NUMBER (TS 102 723-3 clause 5.2.3 wording).
    virtual MF_COMMAND_confirm command(const MF_COMMAND_request& request) {
        return {request.fac_id, request.command_ref, ErrStatus::INVALID_COMMAND_REQUEST_NUMBER};
    }
    virtual MF_REQUEST_confirm request(const MF_REQUEST_request& request) {
        return {request.fac_id, request.command_ref, ErrStatus::INVALID_COMMAND_REQUEST_NUMBER, {}};
    }
};

bool f_param_value_in_format(F_Param_No, std::uint32_t value);

/** MF-SET over a sink; format checked first (Table 13), a null sink answers UNSUPPORTED. */
MF_SET_confirm MF_SET_request_submit(FacilitiesParameterSink*, const MF_SET_request&);
MF_COMMAND_confirm MF_COMMAND_request_submit(FacilitiesParameterSink*, const MF_COMMAND_request&);
MF_REQUEST_confirm MF_REQUEST_request_submit(FacilitiesParameterSink*, const MF_REQUEST_request&);

} // namespace vanetza_idf::MF_SAP
