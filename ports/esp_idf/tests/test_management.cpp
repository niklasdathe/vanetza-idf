// Management-plane bindings: MN-SAP CORE_MMT feed and DCC parameter GET/SET
// over MN/MF/MI with an application-supplied provider, nothing invented.
#include "check.hpp"
#include <vanetza_idf/mf_sap.hpp>
#include <vanetza_idf/mi_sap.hpp>
#include <vanetza_idf/mn_sap.hpp>
#include <vanetza_idf/stack.hpp>
#include <map>
#include <vector>

using namespace vanetza;
using namespace vanetza_idf;
using vidf_test::check;

namespace {
struct Radio : Access {
    std::vector<AlDataRequest> packets;
    Result request(AlDataRequest packet) override { packets.push_back(std::move(packet)); return Result::accepted; }
};

// Access/DCC adapter stand-in that only knows the channel number and TX power limit.
struct DccAdapter : MN_SAP::NetworkParameterProvider, MI_SAP::AccessParameterProvider {
    std::map<int, std::uint32_t> values {{1, 5}, {6, 23}, {52, 5}, {57, 23}};
    MN_SAP::ErrStatus get(MN_SAP::N_Param_No no, std::uint32_t& value) override {
        auto it = values.find(static_cast<int>(no));
        if (it == values.end()) return MN_SAP::ErrStatus::UNSUPPORTED;
        value = it->second;
        return MN_SAP::ErrStatus::SUCCESS;
    }
    MN_SAP::ErrStatus set(MN_SAP::N_Param_No no, std::uint32_t value) override {
        if (!values.count(static_cast<int>(no))) return MN_SAP::ErrStatus::UNSUPPORTED;
        values[static_cast<int>(no)] = value;
        return MN_SAP::ErrStatus::SUCCESS;
    }
    MN_SAP::ErrStatus get(MI_SAP::I_Param_No no, std::uint32_t& value) override {
        auto it = values.find(static_cast<int>(no));
        if (it == values.end()) return MN_SAP::ErrStatus::UNSUPPORTED;
        value = it->second;
        return MN_SAP::ErrStatus::SUCCESS;
    }
    MN_SAP::ErrStatus set(MI_SAP::I_Param_No no, std::uint32_t value) override {
        if (!values.count(static_cast<int>(no))) return MN_SAP::ErrStatus::UNSUPPORTED;
        values[static_cast<int>(no)] = value;
        return MN_SAP::ErrStatus::SUCCESS;
    }
};

struct Facilities : MF_SAP::FacilitiesParameterSink {
    std::vector<MF_SAP::F_Param> received;
    MN_SAP::ErrStatus set(MF_SAP::F_Param_No no, std::uint32_t value) override {
        received.push_back({no, value});
        return MN_SAP::ErrStatus::SUCCESS;
    }
};

void test_core_mmt() {
    ManualRuntime runtime;
    Radio radio;
    StackConfig cfg;
    cfg.mib.itsGnSecurity = false;
    cfg.mib.vanetzaDisableBeaconing = true;
    cfg.mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Managed;
    cfg.mib.itsGnLocalGnAddr.mid({2, 0, 0, 0, 0, 1});
    Stack stack(cfg, runtime, radio);
    MN_SAP::CORE_MMT_response empty;
    check(MN_SAP::CORE_MMT_response_apply(stack, empty) == Result::invalid_argument, "CORE_MMT.response needs a parameter");
    BtpRequest req;
    req.destination_port = 2018; req.destination_port_info = 0; req.data = {1, 2, 3};
    check(stack.request(req) == Result::rejected, "no position before the management entity supplied one");
    // Time and position vector through the management plane (Annex K.3, EN 302 890-2 clause 5.5.2 data set).
    MN_SAP::CORE_MMT_response response;
    response.time = Clock::time_point(std::chrono::seconds(716292005));
    PositionFix fix;
    fix.timestamp = *response.time;
    fix.latitude = 48.1 * units::degree; fix.longitude = 11.6 * units::degree;
    fix.speed = 1.5 * units::si::meters_per_second; fix.course = 90.0 * units::true_north_degrees;
    response.local_position_vector = fix;
    check(MN_SAP::CORE_MMT_response_apply(stack, response) == Result::accepted, "time and position applied");
    check(runtime.now() == *response.time, "time reached the runtime");
    check(stack.request(req) == Result::accepted && radio.packets.size() == 1, "position enables transmission");
    // Managed address configuration (clause 10.2.1.3.3): the SO PV of the next packet carries the new MID.
    MN_SAP::CORE_MMT_response address;
    geonet::Address gn_addr = cfg.mib.itsGnLocalGnAddr;
    gn_addr.mid({2, 0, 0, 0, 0, 9});
    address.geonetworking_address = gn_addr;
    check(MN_SAP::CORE_MMT_response_apply(stack, address) == Result::accepted, "managed address update applied");
    stack.request(req);
    const auto& wire = radio.packets.back();
    check(wire.source == MacAddress {2, 0, 0, 0, 0, 9}, "link-layer source follows the CORE_MMT address");
    // SO PV in an unsecured SHB: Basic (4) + Common (8) headers, then GN_ADDR (2 octets + MID).
    check(wire.data.size() > 18 && std::equal(wire.source.octets.begin(), wire.source.octets.end(), wire.data.begin() + 14),
          "SO PV MID follows the CORE_MMT address");
    check(stack.address().mid() == MacAddress {2, 0, 0, 0, 0, 9}, "Stack::address reports the update");
    MN_SAP::CORE_MMT_response mapping;
    mapping.tc_mapping = std::vector<std::uint8_t> {0};
    check(MN_SAP::CORE_MMT_response_apply(stack, mapping) == Result::unsupported, "TC mapping is not silently accepted");
    MN_SAP::CORE_MMT_response regress;
    regress.time = *response.time - std::chrono::seconds(1);
    check(MN_SAP::CORE_MMT_response_apply(stack, regress) == Result::time_regression, "time regression rejected");
    // Auto configuration refuses an address from the management plane (clause 10.2.1.2).
    StackConfig auto_cfg = cfg;
    auto_cfg.mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Auto;
    Stack auto_stack(auto_cfg, runtime, radio);
    check(MN_SAP::CORE_MMT_response_apply(auto_stack, address) == Result::unsupported, "auto configuration keeps its address");
}

void test_parameter_saps() {
    DccAdapter adapter;
    // MN-GET: known parameters answered, unknown ones reported, no values invented.
    MN_SAP::MN_GET_request get {7, 1, {MN_SAP::N_Param_No::CHANNEL_NUMBER, MN_SAP::N_Param_No::GLOBAL_CBR,
                                       MN_SAP::N_Param_No::TX_POWER_LEVEL_LIMIT}};
    auto got = MN_SAP::MN_GET_request_submit(&adapter, get);
    check(got.nt_id == 7 && got.command_ref == 1, "MN-GET.confirm echoes NT-ID and CommandRef");
    check(got.n_param.size() == 2 && got.n_param[0].no == MN_SAP::N_Param_No::CHANNEL_NUMBER && got.n_param[0].value == 5 &&
          got.n_param[1].value == 23, "provider values returned");
    check(got.errors.size() == 1 && got.errors[0].n_param_no == MN_SAP::N_Param_No::GLOBAL_CBR &&
          got.errors[0].err_status == MN_SAP::ErrStatus::UNSUPPORTED, "unmeasured global CBR is an error, not zero");
    auto none = MN_SAP::MN_GET_request_submit(nullptr, get);
    check(none.n_param.empty() && none.errors.size() == 3, "without a provider every parameter is unsupported");
    // MN-SET: read-only and format violations are refused before the provider.
    MN_SAP::MN_SET_request set {7, 2, {{MN_SAP::N_Param_No::TX_POWER_LEVEL_LIMIT, 20},
                                       {MN_SAP::N_Param_No::LOCAL_CBR, 10},
                                       {MN_SAP::N_Param_No::CHANNEL_NUMBER, 9}}};
    auto set_confirm = MN_SAP::MN_SET_request_submit(&adapter, set);
    check(adapter.values[6] == 20, "writable parameter reached the adapter");
    check(set_confirm.errors.size() == 2 && set_confirm.errors[0].err_status == MN_SAP::ErrStatus::READ_ONLY &&
          set_confirm.errors[1].err_status == MN_SAP::ErrStatus::INVALID_VALUE, "read-only and out-of-format writes reported");
    check(adapter.values[1] == 5, "invalid channel number never reached the adapter");
    // MF-SET: F-Params delivered to the facilities sink; a null sink is unsupported.
    Facilities facilities;
    MF_SAP::MF_SET_request mf {3, 4, {{MF_SAP::F_Param_No::CHANNEL_NUMBER, 5}, {MF_SAP::F_Param_No::AVAILABLE_RESOURCE, 70},
                                      {MF_SAP::F_Param_No::CHANNEL_NUMBER, 0}}};
    auto mf_confirm = MF_SAP::MF_SET_request_submit(&facilities, mf);
    check(facilities.received.size() == 2 && facilities.received[1].value == 70, "MF-SET delivered the resource to the facilities sink");
    check(mf_confirm.fac_id == 3 && mf_confirm.errors.size() == 1 && mf_confirm.errors[0].err_status == MN_SAP::ErrStatus::INVALID_VALUE,
          "channel 0 is outside Table 13");
    check(MF_SAP::MF_SET_request_submit(nullptr, mf).errors.size() == 3, "no sink: every F-Param unsupported");
    MF_SAP::MF_COMMAND_request command {3, 5, 42, {}};
    check(MF_SAP::MF_COMMAND_request_submit(&facilities, command).err_status == MN_SAP::ErrStatus::INVALID_COMMAND_REQUEST_NUMBER,
          "unknown MF-COMMAND acknowledged with ErrStatus 5");
    // MI-GET/SET over the access adapter.
    MI_SAP::MI_GET_request mi_get {1, 6, {MI_SAP::I_Param_No::CHANNEL_NUMBER, MI_SAP::I_Param_No::LOCAL_CBR}};
    auto mi = MI_SAP::MI_GET_request_submit(&adapter, mi_get);
    check(mi.i_param.size() == 1 && mi.i_param[0].value == 5 && mi.errors.size() == 1, "MI-GET: measured value and unmeasured CBR");
    MI_SAP::MI_SET_request mi_set {1, 7, {{MI_SAP::I_Param_No::TX_POWER_LEVEL_LIMIT, 40}, {MI_SAP::I_Param_No::MESSAGE_LENGTH, 1}}};
    auto mi_confirm = MI_SAP::MI_SET_request_submit(&adapter, mi_set);
    check(mi_confirm.errors.size() == 2 && mi_confirm.errors[0].err_status == MN_SAP::ErrStatus::INVALID_VALUE &&
          mi_confirm.errors[1].err_status == MN_SAP::ErrStatus::READ_ONLY && adapter.values[57] == 23,
          "MI-SET refuses 40 dBm and a read-only parameter");
}
} // namespace

void test_management() {
    test_core_mmt();
    test_parameter_saps();
}
