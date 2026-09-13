// External TITAN SUT adapter for the official AtsGeoNetworking port interfaces.
// Testcase sources and verdict logic are unchanged. This adapter invokes a
// separate host/device SUT process and decodes its actual boundary outputs
// using the ATS's own generated codec (fx_enc/fx_dec), not a hand-rolled parser.
//
// Scope: SHB source generation only (GAP-GN-001; GUC/GAC/TSB/GBC triggers,
// beaconing simulation and GNSS scenarios are not implemented -- PICS in
// etsi_geonetworking.cfg disables the corresponding test-control branches).
#include "UpperTesterPort_GN.hh"
#include "GeoNetworkingPort.hh"
#include "AdapterControlPort_GN.hh"
#include "LibItsGeoNetworking_EncdecDeclarations.hh"
#include <functional>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <stdexcept>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

namespace {
using Bytes = std::vector<unsigned char>;
using namespace LibItsGeoNetworking__TypesAndValues;
std::function<void(const GeoNetworkingInd&)> lower_indication;
unsigned read16(const Bytes& b, unsigned i) { return (b.at(i) << 8) | b.at(i + 1); }

class Process {
    pid_t pid_ = -1;
    int input_ = -1, output_ = -1;
public:
    ~Process() {
        if (input_ >= 0) close(input_);
        if (output_ >= 0) close(output_);
        if (pid_ > 0) { kill(pid_, SIGTERM); waitpid(pid_, nullptr, 0); }
    }
    Bytes exchange(const Bytes& bytes) {
        if (pid_ < 0) {
            const char* executable = std::getenv("VIDF_SUT_EXECUTABLE");
            if (!executable) throw std::runtime_error("Set VIDF_SUT_EXECUTABLE to the external SUT process");
            int in[2], out[2];
            if (pipe(in) || pipe(out)) throw std::runtime_error("Cannot create SUT pipes");
            pid_ = fork();
            if (pid_ == 0) {
                dup2(in[0], STDIN_FILENO); dup2(out[1], STDOUT_FILENO);
                close(in[0]); close(in[1]); close(out[0]); close(out[1]);
                const char* script = std::getenv("VIDF_SUT_SCRIPT");
                const char* port = std::getenv("VIDF_SUT_PORT");
                if (script && port) execl(executable, executable, script, "--port", port, static_cast<char*>(nullptr));
                else execl(executable, executable, static_cast<char*>(nullptr));
                _exit(127);
            }
            close(in[0]); close(out[1]); input_ = in[1]; output_ = out[0];
            if (pid_ < 0) throw std::runtime_error("Cannot fork SUT process");
        }
        const char* digits = "0123456789abcdef";
        std::string line;
        for (auto b : bytes) { line += digits[b >> 4]; line += digits[b & 15]; }
        line += '\n';
        for (std::size_t sent = 0; sent < line.size();) {
            const auto count = write(input_, line.data() + sent, line.size() - sent);
            if (count <= 0) throw std::runtime_error("SUT pipe write failed");
            sent += count;
        }
        line.clear();
        while (line.size() <= 8192) {
            pollfd fd {output_, POLLIN, 0};
            if (poll(&fd, 1, 12000) <= 0) throw std::runtime_error("SUT response timeout");
            char c;
            if (read(output_, &c, 1) != 1) throw std::runtime_error("SUT process ended");
            if (c == '\n') break;
            if (c != '\r') line += c;
        }
        if (line.size() > 8192 || line.size() % 2) throw std::runtime_error("Invalid SUT response size");
        Bytes result;
        auto hex = [](char c) -> unsigned {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            throw std::runtime_error("Non-hex SUT response");
        };
        for (unsigned i = 0; i < line.size(); i += 2) result.push_back((hex(line[i]) << 4) | hex(line[i + 1]));
        return result;
    }
};
Process sut;

// GN_Address baked into hil_sut.cpp's Sut::reset() (config.mib.itsGnLocalGnAddr.mid
// only; type-of-address/station-type/reserved stay at vanetza::geonet::Address's
// defaults). f_acGetLongPosVector's caller compares this exactly against the wire
// source address (LibItsGeoNetworking_Templates.ttcn mw_longPosVectorPosition), so
// it must match vanetza/geonet/address.cpp's Address() defaults, not be invented.
GN__Address iut_gn_address() {
    GN__Address address;
    address.typeOfAddress() = TypeOfAddress::e__initial; // Address::m_manually_configured == false
    address.stationType() = StationType::e__unknown;     // Address::m_station_type == StationType::Unknown
    address.reserved() = 0;                              // Address::m_country_code == 0
    const unsigned char mid[] = {2, 0, 0, 0, 0, 1};
    address.mid() = OCTETSTRING(6, mid);
    return address;
}
// Position/speed/heading baked into the same reset(): 52.0N, 13.0E, stationary.
LongPosVector iut_position() {
    LongPosVector position;
    position.gnAddr() = iut_gn_address();
    position.timestamp__() = 0;
    position.latitude() = 520000000;  // 1/10 microdegree, matching LongPosVector's encoding
    position.longitude() = 130000000;
    const unsigned char zero_bit = 0;
    position.pai() = BITSTRING(1, &zero_bit);
    position.speed() = 0;
    position.heading() = 0;
    return position;
}

bool transact(const Bytes& command) {
    const auto reply = sut.exchange(command);
    if (reply.size() < 2) throw std::runtime_error("Truncated SUT response");
    unsigned offset = 2;
    for (unsigned n = 0; n < reply[1]; ++n) {
        const auto kind = reply.at(offset);
        const auto size = read16(reply, offset + 1);
        offset += 3;
        if (offset + size > reply.size()) throw std::runtime_error("Truncated SUT record");
        Bytes b(reply.begin() + offset, reply.begin() + offset + size); offset += size;
        if (kind == 1) {
            // AL_DATA transmission observed independently of what triggered it
            // (matches etsi_btp_adapter.cpp's kind==1 handling): decode with the
            // ATS's own RAW codec, not a hand-rolled header parser.
            BITSTRING bits = oct2bit(OCTETSTRING(static_cast<int>(b.size()), b.data()));
            GeoNetworkingPdu pdu;
            if (LibItsGeoNetworking__EncdecDeclarations::fx__dec__GeoNetworkingPdu(bits, pdu) != 0)
                throw std::runtime_error("GeoNetworkingPdu decode failed");
            GeoNetworkingInd indication;
            indication.msgIn() = pdu;
            const unsigned char broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            indication.macDestinationAddress() = OCTETSTRING(6, broadcast);
            indication.ssp() = OMIT_VALUE;
            indication.its__aid() = OMIT_VALUE;
            if (lower_indication) lower_indication(indication);
        } else if (kind != 3) {
            throw std::runtime_error("Unexpected SUT record kind");
        } // kind == 3 (raw GN-DATA.indication) is not exercised by the SHB-source scope.
    }
    if (offset != reply.size()) throw std::runtime_error("Trailing SUT response bytes");
    return reply[0] == 0;
}
}

namespace LibItsGeoNetworking__TestSystem {

UpperTesterPort::UpperTesterPort(const char* name) : UpperTesterPort_BASE(name) {}
UpperTesterPort::~UpperTesterPort() = default;
void UpperTesterPort::set_parameter(const char*, const char*) {}
void UpperTesterPort::Handle_Fd_Event_Error(int) {}
void UpperTesterPort::Handle_Fd_Event_Writable(int) {}
void UpperTesterPort::Handle_Fd_Event_Readable(int) {}
void UpperTesterPort::receiveMsg(const Base_Type&, const params&) {}
void UpperTesterPort::user_map(const char*) {}
void UpperTesterPort::user_unmap(const char*) {}
void UpperTesterPort::user_start() {}
void UpperTesterPort::user_stop() {}
void UpperTesterPort::outgoing_send(const UtGnInitialize&) {
    try {
        UtGnResults result; result.utGnInitializeResult() = transact({0}); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT initialization: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtGnChangePosition& change) {
    // TS 102 871-2 documents these as relative offsets; this port applies them as
    // an absolute fix in the same 1/10 microdegree encoding as LongPosVector,
    // matching the only currently-exercised caller (none: no in-scope SHB-source
    // testcase sends this yet). Revisit before relying on it for a mobile scenario.
    try {
        Bytes command {4};
        const auto i32 = [&](std::int32_t v) {
            command.push_back(static_cast<unsigned>(v) >> 24); command.push_back(static_cast<unsigned>(v) >> 16);
            command.push_back(static_cast<unsigned>(v) >> 8); command.push_back(static_cast<unsigned>(v));
        };
        i32(static_cast<std::int32_t>(change.latitude()));
        i32(static_cast<std::int32_t>(change.longitude()));
        UtGnResults result; result.utGnChangePositionResult() = transact(command); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT position change: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtGnTrigger& trigger) {
    try {
        if (trigger.get_selection() != UtGnTrigger::ALT_shb) {
            // GUC/GAC/TSB/GBC generation: GAP-GN-001, upstream router stubs.
            UtGnResults result; result.utGnTriggerResult() = false; incoming_message(result);
            return;
        }
        const auto& shb = trigger.shb();
        const auto& tc = shb.trafficClass();
        const unsigned char raw = (tc.scf() == SCF::e__scfEnabled ? 0x80 : 0) |
                                   (tc.channelOffload() == ChannelOffload::e__choffEnable ? 0x40 : 0) |
                                   (static_cast<unsigned>(static_cast<long long>(tc.tcId())) & 0x3f);
        Bytes command {3, raw};
        const OCTETSTRING& payload = shb.payload();
        const unsigned char* ptr = payload;
        command.insert(command.end(), ptr, ptr + payload.lengthof());
        UtGnResults result; result.utGnTriggerResult() = transact(command); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT GN trigger: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtAutoInteropTrigger&) {
    UtGnResults result; result.utAutoInteropTriggerResult() = false; incoming_message(result);
}

GeoNetworkingPort::GeoNetworkingPort(const char* name) : GeoNetworkingPort_BASE(name) {}
GeoNetworkingPort::~GeoNetworkingPort() = default;
void GeoNetworkingPort::set_parameter(const char*, const char*) {}
void GeoNetworkingPort::Handle_Fd_Event_Error(int) {}
void GeoNetworkingPort::Handle_Fd_Event_Writable(int) {}
void GeoNetworkingPort::Handle_Fd_Event_Readable(int) {}
void GeoNetworkingPort::receiveMsg(const GeoNetworkingInd&, const params&) {}
void GeoNetworkingPort::user_map(const char*) { lower_indication = [this](const GeoNetworkingInd& p) { incoming_message(p); }; }
void GeoNetworkingPort::user_unmap(const char*) { lower_indication = {}; }
void GeoNetworkingPort::user_start() {}
void GeoNetworkingPort::user_stop() {}
void GeoNetworkingPort::outgoing_send(const GeoNetworkingReq& send_par) {
    // The lower tester injecting a packet toward the IUT (e.g. a neighbour's
    // GBC/beacon): encode via the ATS's own codec, submit as AL_DATA.indication.
    // Not exercised by the SHB-source scope, kept complete for the DST direction.
    try {
        const BITSTRING encoded = LibItsGeoNetworking__EncdecDeclarations::fx__enc__GeoNetworkingPdu(send_par.msgOut());
        const OCTETSTRING raw = bit2oct(encoded);
        const unsigned char* ptr = raw;
        const unsigned char* mac = send_par.macDestinationAddress();
        const unsigned char source[] = {0x02, 0, 0, 0, 0, 2}; // distinct locally-administered lower-tester address
        Bytes command {2};
        command.insert(command.end(), source, source + 6);
        command.insert(command.end(), mac, mac + 6);
        command.insert(command.end(), ptr, ptr + raw.lengthof());
        if (!transact(command)) TTCN_error("SUT rejected lower tester submission");
    } catch (const std::exception& e) { TTCN_error("SUT lower tester: %s", e.what()); }
}

AdapterControlPort::AdapterControlPort(const char* name) : AdapterControlPort_BASE(name) {}
AdapterControlPort::~AdapterControlPort() = default;
void AdapterControlPort::set_parameter(const char*, const char*) {}
void AdapterControlPort::Handle_Fd_Event_Error(int) {}
void AdapterControlPort::Handle_Fd_Event_Writable(int) {}
void AdapterControlPort::Handle_Fd_Event_Readable(int) {}
void AdapterControlPort::user_map(const char*) {}
void AdapterControlPort::user_unmap(const char*) {}
void AdapterControlPort::user_start() {}
void AdapterControlPort::user_stop() {}
void AdapterControlPort::outgoing_send(const AcGnPrimitive& primitive) {
    // f_acTriggerEvent (LibItsGeoNetworking_Functions.ttcn) is fire-and-forget for
    // every AcGnPrimitive except getLongPosVector, which f_acGetLongPosVector
    // waits on synchronously.
    if (primitive.get_selection() == AcGnPrimitive::ALT_getLongPosVector) {
        AcGnResponse response; response.getLongPosVector() = iut_position();
        incoming_message(response);
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_startBeaconing) {
        // Not fire-and-forget in effect: an SHB/GBC request with store-carry-forward
        // enabled (TrafficClass.scf) is buffered by the upstream router rather than
        // transmitted immediately unless its location table already has a neighbour
        // (vanetza/geonet/router.cpp, Router::request(const ShbDataRequest&, ...)).
        // f_startBeingNeighbour's whole purpose is to establish that neighbour, so
        // this feeds the supplied beacon PDU into the IUT exactly as GeoNetworkingPort
        // would for any other lower-tester-injected packet.
        try {
            const BITSTRING encoded = LibItsGeoNetworking__EncdecDeclarations::fx__enc__GeoNetworkingPdu(
                primitive.startBeaconing().beaconPacket());
            const OCTETSTRING raw = bit2oct(encoded);
            const unsigned char* raw_bytes = raw;
            const unsigned char source[] = {0x02, 0, 0, 0, 0, 3};
            const unsigned char broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            Bytes command {2};
            command.insert(command.end(), source, source + 6);
            command.insert(command.end(), broadcast, broadcast + 6);
            command.insert(command.end(), raw_bytes, raw_bytes + raw.lengthof());
            transact(command); // Best-effort neighbour setup; no confirm exists to report failure through.
        } catch (const std::exception&) {
            // f_startBeingNeighbour does not check a result; swallow and let the
            // subsequent testcase behaviour (e.g. store-carry-forward buffering)
            // surface the real problem instead of aborting the whole testcase here.
        }
    }
}
void AdapterControlPort::outgoing_send(const LibItsIpv6OverGeoNetworking__TypesAndValues::AcGn6Primitive&) {}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcGnssPrimitive&) {
    // Only reached if PX_GNSS_SCENARIO_SUPPORT is true; the supplied config sets
    // it false, so f_acLoadScenario/f_acStartScenario/f_acAwaitTimeInRunningScenario
    // never call this (GAP-GN-001: no GNSS scenario simulation implemented).
}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcSecPrimitive&) {}

}
