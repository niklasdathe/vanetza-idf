// Management-plane bindings: MN-SAP (TS 102 723-4, TS 103 836-4-1 Annex K,
// TS 103 175 clause 8.3), MF-SAP (TS 102 723-5, TS 103 175 clause 8.4) and
// MI-SAP (TS 102 723-3, TS 103 175 clause 8.2). Values only ever come from the
// providers the application registers.
#include <vanetza_idf/mf_sap.hpp>
#include <vanetza_idf/mi_sap.hpp>
#include <vanetza_idf/mn_sap.hpp>

namespace vanetza_idf {
namespace {
// Shared GET/SET machinery: format check, access check, then the provider.
template<class No, class Param, class Error, class Provider>
void get_all(Provider* provider, const std::vector<No>& numbers, bool (*in_format)(No, std::uint32_t),
             std::vector<Param>& out, std::vector<Error>& errors) {
    for (auto no : numbers) {
        std::uint32_t value = 0;
        auto status = provider ? provider->get(no, value) : MN_SAP::ErrStatus::UNSUPPORTED;
        if (status == MN_SAP::ErrStatus::SUCCESS && !in_format(no, value)) status = MN_SAP::ErrStatus::INVALID_VALUE;
        if (status == MN_SAP::ErrStatus::SUCCESS) out.push_back(Param {no, value});
        else errors.push_back(Error {no, status});
    }
}
template<class No, class Param, class Error, class Provider>
void set_all(Provider* provider, const std::vector<Param>& params, bool (*in_format)(No, std::uint32_t),
             bool (*writable)(No), std::vector<Error>& errors) {
    for (const auto& param : params) {
        MN_SAP::ErrStatus status;
        if (!writable(param.no)) status = MN_SAP::ErrStatus::READ_ONLY;
        else if (!in_format(param.no, param.value)) status = MN_SAP::ErrStatus::INVALID_VALUE;
        else status = provider ? provider->set(param.no, param.value) : MN_SAP::ErrStatus::UNSUPPORTED;
        if (status != MN_SAP::ErrStatus::SUCCESS) errors.push_back(Error {param.no, status});
    }
}
} // namespace

namespace MN_SAP {
Result CORE_MMT_response_apply(Stack& stack, const CORE_MMT_response& response) {
    if (!response.time && !response.local_position_vector && !response.geonetworking_address && !response.tc_mapping)
        return Result::invalid_argument; // clause K.3: at least one parameter is present
    if (response.time) {
        const auto result = stack.advance(*response.time);
        if (result != Result::accepted) return result;
    }
    if (response.local_position_vector) {
        const auto result = stack.update_position(*response.local_position_vector);
        if (result != Result::accepted) return result;
    }
    if (response.geonetworking_address) {
        const auto result = stack.set_address(*response.geonetworking_address);
        if (result != Result::accepted) return result;
    }
    if (response.tc_mapping) return Result::unsupported; // fixed TS 102 687 mapping in this port
    return Result::accepted;
}

bool n_param_value_in_format(N_Param_No no, std::uint32_t value) {
    switch (no) { // TS 103 175 Table 10 formats
        case N_Param_No::GLOBAL_CBR:
        case N_Param_No::LOCAL_CBR: return value <= 100;
        case N_Param_No::CHANNEL_NUMBER: return value >= 1 && value <= 7;
        case N_Param_No::AVAILABLE_RESOURCE:
        case N_Param_No::IDLE_TIME: return value <= 0xffff;
        case N_Param_No::LAST_TRANSMIT_TIME: return true;
        case N_Param_No::TX_POWER_LEVEL_LIMIT: return value <= 31; // bits 5..7 reserved
    }
    return false;
}
bool n_param_writable(N_Param_No no) {
    return no == N_Param_No::CHANNEL_NUMBER || no == N_Param_No::IDLE_TIME || no == N_Param_No::TX_POWER_LEVEL_LIMIT;
}
MN_GET_confirm MN_GET_request_submit(NetworkParameterProvider* provider, const MN_GET_request& request) {
    MN_GET_confirm confirm {request.nt_id, request.command_ref, {}, {}};
    get_all<N_Param_No, N_Param, N_Error>(provider, request.n_param_no, n_param_value_in_format, confirm.n_param, confirm.errors);
    return confirm;
}
MN_SET_confirm MN_SET_request_submit(NetworkParameterProvider* provider, const MN_SET_request& request) {
    MN_SET_confirm confirm {request.nt_id, request.command_ref, {}};
    set_all<N_Param_No, N_Param, N_Error>(provider, request.n_param, n_param_value_in_format, n_param_writable, confirm.errors);
    return confirm;
}
} // namespace MN_SAP

namespace MF_SAP {
bool f_param_value_in_format(F_Param_No no, std::uint32_t value) {
    switch (no) { // TS 103 175 Table 13 formats
        case F_Param_No::CHANNEL_NUMBER: return value >= 1 && value <= 7;
        case F_Param_No::AVAILABLE_RESOURCE: return value <= 0xffff;
    }
    return false;
}
MF_SET_confirm MF_SET_request_submit(FacilitiesParameterSink* sink, const MF_SET_request& request) {
    MF_SET_confirm confirm {request.fac_id, request.command_ref, {}};
    for (const auto& param : request.f_param) {
        ErrStatus status;
        if (!f_param_value_in_format(param.no, param.value)) status = ErrStatus::INVALID_VALUE;
        else status = sink ? sink->set(param.no, param.value) : ErrStatus::UNSUPPORTED;
        if (status != ErrStatus::SUCCESS) confirm.errors.push_back(F_Error {param.no, status});
    }
    return confirm;
}
MF_COMMAND_confirm MF_COMMAND_request_submit(FacilitiesParameterSink* sink, const MF_COMMAND_request& request) {
    if (!sink) return {request.fac_id, request.command_ref, ErrStatus::UNSUPPORTED};
    return sink->command(request);
}
MF_REQUEST_confirm MF_REQUEST_request_submit(FacilitiesParameterSink* sink, const MF_REQUEST_request& request) {
    if (!sink) return {request.fac_id, request.command_ref, ErrStatus::UNSUPPORTED, {}};
    return sink->request(request);
}
} // namespace MF_SAP

namespace MI_SAP {
bool i_param_value_in_format(I_Param_No no, std::uint32_t value) {
    switch (no) { // TS 103 175 Table 5 formats
        case I_Param_No::CHANNEL_NUMBER: return value >= 1 && value <= 7;
        case I_Param_No::LOCAL_CBR: return value <= 100;
        case I_Param_No::MESSAGE_LENGTH: return value <= 0xff;
        case I_Param_No::LAST_TRANSMIT_TIME: return true;
        case I_Param_No::IDLE_TIME: return value <= 0xffff;
        case I_Param_No::TX_POWER_LEVEL_LIMIT: return value <= 31;
    }
    return false;
}
bool i_param_writable(I_Param_No no) {
    return no == I_Param_No::CHANNEL_NUMBER || no == I_Param_No::IDLE_TIME || no == I_Param_No::TX_POWER_LEVEL_LIMIT;
}
MI_GET_confirm MI_GET_request_submit(AccessParameterProvider* provider, const MI_GET_request& request) {
    MI_GET_confirm confirm {request.mac_id, request.command_ref, {}, {}};
    get_all<I_Param_No, I_Param, I_Error>(provider, request.i_param_no, i_param_value_in_format, confirm.i_param, confirm.errors);
    return confirm;
}
MI_SET_confirm MI_SET_request_submit(AccessParameterProvider* provider, const MI_SET_request& request) {
    MI_SET_confirm confirm {request.mac_id, request.command_ref, {}};
    set_all<I_Param_No, I_Param, I_Error>(provider, request.i_param, i_param_value_in_format, i_param_writable, confirm.errors);
    return confirm;
}
} // namespace MI_SAP
} // namespace vanetza_idf
