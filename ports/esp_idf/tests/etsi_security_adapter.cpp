// External TITAN SUT adapter for the official AtsSecurity port interfaces
// (system ItsSecSystem: the GeoNetworking ports plus the CAM and DENM upper
// tester ports). Testcase sources and verdict logic are unchanged. The
// adapter drives a separate host SUT process (vidf_sut --security-pool ...)
// through the diagnostic protocol of hil_sut.hpp and decodes what that SUT
// actually transmits with the ATS's own generated codec (fx_enc/fx_dec).
//
// Scope: sending behaviour of the IUT (GN-MGMT beacons through the GN core,
// CAM and DENM carriers emitted by the test application, TS 103 097 security
// profiles). Receiving-side cases need SN-DECAP verification (GAP-SEC-001) and
// are not wired; etsi_security_gn.cfg and etsi_security_facilities.cfg keep the
// PICS honest and select the stimulus configuration (CAM carrier on or off).
//
// Time: the SUT owns an ITS clock that this adapter advances to wall-clock
// ITS time every 100 ms (timerfd on the GeoNetworking port); spontaneous
// transmissions (beacons, periodic CAM carrier) come back with each tick.
#include "UpperTesterPort_GN.hh"
#include "GeoNetworkingPort.hh"
#include "AdapterControlPort_GN.hh"
#include "UpperTesterPort_CAM.hh"
#include "UpperTesterPort_DENM.hh"
#include "LibItsGeoNetworking_EncdecDeclarations.hh"
#include "geonetworking_codec.hh"
#include "security_services_its.hh"
#include "params_its.hh"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <cerrno>
#include <pthread.h>

namespace {
using Bytes = std::vector<unsigned char>;
using namespace LibItsGeoNetworking__TypesAndValues;
std::function<void(const GeoNetworkingInd&)> lower_indication;
unsigned read16(const Bytes& b, unsigned i) { return (b.at(i) << 8) | b.at(i + 1); }

// GN layer parameters of the test system, taken from the geoNetworkingPort "params"
// test port parameter in the framework's own "GN(key=value,...)/..." syntax so the cfg
// reads like an official one. Only the security keys are meaningful here:
// enable_security_checks (failed verification discards the packet instead of warning)
// and sec_db_path (certificate pool loaded at map time, as geonetworking_layer does).
params_its gn_params;
bool security_checks_default = false;
bool security_checks = false;

void parse_gn_params(const std::string& value) {
    const auto begin = value.find("GN(");
    if (begin == std::string::npos) return;
    const auto end = value.find(')', begin);
    params::convert(gn_params, value.substr(begin + 3, end == std::string::npos ? std::string::npos : end - begin - 3));
    security_checks_default = gn_params.count(params_its::enable_security_checks) && gn_params[params_its::enable_security_checks] == "1";
    security_checks = security_checks_default;
}

// ITS time (TAI microseconds since 2004-01-01T00:00:00Z): UTC plus the leap seconds
// inserted since 2004 (2005-12, 2008-12, 2012-06, 2015-06, 2016-12).
std::uint64_t its_now_us() {
    const auto unix_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    constexpr std::int64_t epoch_2004_us = 1072915200LL * 1000000LL;
    return static_cast<std::uint64_t>(unix_us - epoch_2004_us + 5LL * 1000000LL);
}

// The external SUT process. TITAN's parallel runtime forks the MTC and every PTC from
// the host controller, and a test case may drive the IUT from several components (the
// DENM cases trigger from a PTC while the MTC observes the GN port). One SUT instance
// is therefore started in the host controller before any fork, its pipes are inherited
// by every component, and a process-shared robust mutex keeps each command/reply
// exchange atomic across components. Only the process that spawned the SUT stops it.
class Process {
    pid_t pid_ = -1, owner_ = -1;
    int input_ = -1, output_ = -1;
    pthread_mutex_t* lock_ = nullptr;
public:
    Process() {
        const char* executable = std::getenv("VIDF_SUT_EXECUTABLE");
        if (!executable) return; // reported on first use
        void* shared = mmap(nullptr, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (shared == MAP_FAILED) return;
        lock_ = static_cast<pthread_mutex_t*>(shared);
        pthread_mutexattr_t attributes;
        pthread_mutexattr_init(&attributes);
        pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(lock_, &attributes);
        pthread_mutexattr_destroy(&attributes);
        // VIDF_SUT_ARGS: space separated arguments, e.g. "--security-pool /path/to/pool"
        std::vector<std::string> args {executable};
        if (const char* extra = std::getenv("VIDF_SUT_ARGS")) {
            std::istringstream stream(extra);
            for (std::string arg; stream >> arg;) args.push_back(arg);
        }
        int in[2], out[2];
        if (pipe(in) || pipe(out)) return;
        pid_ = fork();
        if (pid_ == 0) {
            dup2(in[0], STDIN_FILENO); dup2(out[1], STDOUT_FILENO);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            std::vector<char*> argv;
            for (auto& arg : args) argv.push_back(arg.data());
            argv.push_back(nullptr);
            execv(executable, argv.data());
            _exit(127);
        }
        close(in[0]); close(out[1]); input_ = in[1]; output_ = out[0];
        owner_ = getpid();
    }
    ~Process() {
        if (pid_ > 0 && getpid() == owner_) { kill(pid_, SIGTERM); waitpid(pid_, nullptr, 0); }
    }
    Bytes exchange(const Bytes& bytes) {
        if (pid_ <= 0 || !lock_) throw std::runtime_error("Set VIDF_SUT_EXECUTABLE to the external SUT process");
        struct Guard {
            pthread_mutex_t* lock;
            explicit Guard(pthread_mutex_t* l) : lock(l) {
                if (pthread_mutex_lock(lock) == EOWNERDEAD) pthread_mutex_consistent(lock); // a component died mid-exchange
            }
            ~Guard() { pthread_mutex_unlock(lock); }
        } guard(lock_);
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
Process sut; // static initialisation: runs in the host controller before TITAN forks components

// GN address and position baked into hil_sut.cpp's Sut::reset(); see the GeoNetworking
// adapter for why these must match vanetza::geonet::Address's defaults exactly.
GN__Address iut_gn_address() {
    GN__Address address;
    address.typeOfAddress() = TypeOfAddress::e__initial;
    address.stationType() = StationType::e__unknown;
    address.reserved() = 0;
    const unsigned char mid[] = {2, 0, 0, 0, 0, 1};
    address.mid() = OCTETSTRING(6, mid);
    return address;
}
LongPosVector iut_position() {
    LongPosVector position;
    position.gnAddr() = iut_gn_address();
    position.timestamp__() = 0;
    position.latitude() = 520000000;
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
            // AL_DATA transmission observed on the lower boundary, processed the way the
            // framework's geonetworking_layer::receive_data does it: a secured packet (basic
            // header next header 2, TS 103 836-4-1 clause 9.6.1) is verified and unwrapped
            // by the framework's own security services (IEEE 1609.2 / TS 103 097 codec,
            // signature check against the certificate pool), then the basic header plus the
            // extracted GN payload is decoded with the ATS codec and the secured message is
            // attached to the indication (mw_geoNwSecPdu matches on it).
            OCTETSTRING data(static_cast<int>(b.size()), b.data());
            params_its params;
            Ieee1609Dot2::Ieee1609Dot2Data secured_message;
            if (b.size() > 4 && (b[0] & 0x0f) == 2) {
                const OCTETSTRING secured(static_cast<int>(b.size() - 4), b.data() + 4);
                OCTETSTRING unsecured;
                const int verified = security_services_its::get_instance().verify_and_extract_gn_payload(
                    secured, security_checks, secured_message, unsecured, params);
                if (verified != 0) {
                    TTCN_warning("Secured GN packet failed the test system's security processing (checks %s)",
                                 security_checks ? "enforced: discarded" : "not enforced: passed up");
                    if (security_checks) continue;
                }
                data = OCTETSTRING(4, b.data()) + unsecured;
            }
            geonetworking_codec codec;
            GeoNetworkingPdu pdu;
            if (codec.decode(data, pdu, &params) == -1) throw std::runtime_error("GeoNetworkingPdu decode failed");
            if (secured_message.is_bound()) pdu.gnPacket().securedMsg() = OPTIONAL<Ieee1609Dot2::Ieee1609Dot2Data>(secured_message);
            GeoNetworkingInd indication;
            indication.msgIn() = pdu;
            const unsigned char broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            indication.macDestinationAddress() = OCTETSTRING(6, broadcast);
            if (params.count(params_its::ssp)) indication.ssp() = oct2bit(str2oct(CHARSTRING(params[params_its::ssp].c_str())));
            else indication.ssp() = OMIT_VALUE;
            if (params.count(params_its::its_aid)) indication.its__aid() = INTEGER(std::stoi(params[params_its::its_aid]));
            else indication.its__aid() = OMIT_VALUE;
            if (lower_indication) lower_indication(indication);
        } else if (kind != 2 && kind != 3) {
            throw std::runtime_error("Unexpected SUT record kind");
        } // kinds 2/3: BTP/GN indications of received packets, not observed by this campaign
    }
    if (offset != reply.size()) throw std::runtime_error("Trailing SUT response bytes");
    return reply[0] == 0;
}

// One SUT tick: advance the ITS clock to now; transmissions arrive through transact().
void tick() {
    const std::uint64_t now = its_now_us();
    Bytes command {5};
    for (int shift = 56; shift >= 0; shift -= 8) command.push_back(static_cast<unsigned char>(now >> shift));
    transact(command);
}

// Stimulus configuration of the test application behind the GN upper tester port
// (utPort "params": cam_carrier_ms=<period>). A running CAM carrier restarts the beacon
// timer with every SHB it sends (TS 103 836-4-1 clause 10.3.5), so the GN-MGMT cases
// run without it and the CAM/DENM cases with it: two campaign configurations, no
// per-testcase switching inside the adapter.
unsigned cam_carrier_ms = 0;

int timer_fd = -1;
unsigned denm_sequence = 0;
}

namespace LibItsGeoNetworking__TestSystem {

UpperTesterPort::UpperTesterPort(const char* name) : UpperTesterPort_BASE(name) {}
UpperTesterPort::~UpperTesterPort() = default;
void UpperTesterPort::set_parameter(const char* name, const char* value) {
    if (std::strcmp(name, "params") != 0) return;
    params ut_params;
    params::convert(ut_params, value);
    if (ut_params.count("cam_carrier_ms")) cam_carrier_ms = static_cast<unsigned>(std::atoi(ut_params["cam_carrier_ms"].c_str()));
}
void UpperTesterPort::Handle_Fd_Event_Error(int) {}
void UpperTesterPort::Handle_Fd_Event_Writable(int) {}
void UpperTesterPort::Handle_Fd_Event_Readable(int) {}
void UpperTesterPort::receiveMsg(const Base_Type&, const params&) {}
void UpperTesterPort::user_map(const char*) {}
void UpperTesterPort::user_unmap(const char*) {}
void UpperTesterPort::user_start() {}
void UpperTesterPort::user_stop() {}
void UpperTesterPort::outgoing_send(const UtGnInitialize&) {
    // m_secGnInitialize carries the HashedId8 of the certificate the IUT shall use; the SUT
    // is started with that certificate (VIDF_SUT_ARGS --at ...), a mismatch shows up as a
    // signature/digest failure in the testcase rather than being papered over here.
    try {
        bool ok = transact({0});
        tick();
        // Periodic CAM carrier (test-application behaviour, TS 103 097 clause 7.1.1 profile):
        // the CAM cases wait for CAMs the IUT sends on its own.
        if (ok && cam_carrier_ms)
            ok = transact({7, 0, static_cast<unsigned char>(cam_carrier_ms >> 8), static_cast<unsigned char>(cam_carrier_ms)});
        UtGnResults result; result.utGnInitializeResult() = ok; incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT initialization: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtGnChangePosition& change) {
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
            UtGnResults result; result.utGnTriggerResult() = false; incoming_message(result); // GAP-GN-001
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
void GeoNetworkingPort::set_parameter(const char* name, const char* value) {
    if (std::strcmp(name, "params") == 0) parse_gn_params(value);
}
void GeoNetworkingPort::Handle_Fd_Event_Error(int) {}
void GeoNetworkingPort::Handle_Fd_Event_Writable(int) {}
void GeoNetworkingPort::Handle_Fd_Event_Readable(int fd) {
    if (fd != timer_fd) return;
    std::uint64_t expirations = 0;
    if (read(timer_fd, &expirations, sizeof(expirations)) != sizeof(expirations)) return;
    try { tick(); } catch (const std::exception& e) { TTCN_error("SUT tick: %s", e.what()); }
}
void GeoNetworkingPort::receiveMsg(const GeoNetworkingInd&, const params&) {}
void GeoNetworkingPort::user_map(const char*) {
    lower_indication = [this](const GeoNetworkingInd& p) { incoming_message(p); };
    // Certificate pool for the verification of IUT transmissions. The testcases load the
    // same pool through fx_loadCertificates (PX_CERTIFICATE_POOL_PATH/PX_IUT_SEC_CONFIG_NAME)
    // in this component's process; a sec_db_path port parameter makes the mapping
    // self-sufficient, mirroring geonetworking_layer::setup_secured_mode.
    if (gn_params.count(params_its::sec_db_path) && security_services_its::get_instance().setup(gn_params) != 0)
        TTCN_error("Certificate pool %s could not be loaded", gn_params[params_its::sec_db_path].c_str());
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) TTCN_error("timerfd_create failed");
    itimerspec period {};
    period.it_interval.tv_nsec = 100 * 1000 * 1000;
    period.it_value.tv_nsec = 100 * 1000 * 1000;
    timerfd_settime(timer_fd, 0, &period, nullptr);
    Handler_Add_Fd_Read(timer_fd);
}
void GeoNetworkingPort::user_unmap(const char*) {
    if (timer_fd >= 0) { Handler_Remove_Fd_Read(timer_fd); close(timer_fd); timer_fd = -1; }
    lower_indication = {};
}
void GeoNetworkingPort::user_start() {}
void GeoNetworkingPort::user_stop() {}
void GeoNetworkingPort::outgoing_send(const GeoNetworkingReq& send_par) {
    // Lower tester packet toward the IUT (e.g. the test system acting as a neighbour).
    try {
        const BITSTRING encoded = LibItsGeoNetworking__EncdecDeclarations::fx__enc__GeoNetworkingPdu(send_par.msgOut());
        const OCTETSTRING raw = bit2oct(encoded);
        const unsigned char* ptr = raw;
        const unsigned char* mac = send_par.macDestinationAddress();
        const unsigned char source[] = {0x02, 0, 0, 0, 0, 2};
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
    if (primitive.get_selection() == AcGnPrimitive::ALT_getLongPosVector) {
        AcGnResponse response; response.getLongPosVector() = iut_position();
        incoming_message(response);
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_startBeaconing) {
        // f_startBeingNeighbour: feed the test system's beacon into the IUT so its location
        // table holds a neighbour (see the GeoNetworking adapter for the SCF rationale).
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
            transact(command);
        } catch (const std::exception&) {}
    }
    // startPassBeaconing/stopPassBeaconing: this adapter passes every IUT transmission up anyway.
}
void AdapterControlPort::outgoing_send(const LibItsIpv6OverGeoNetworking__TypesAndValues::AcGn6Primitive&) {}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcGnssPrimitive&) {}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcSecPrimitive& primitive) {
    // f_acTriggerSecEvent waits for AdapterControlResults{acSecResponse}. AcEnableSecurity
    // names the certificate the *test system* signs with and whether security failures
    // are enforced (geonetworking_layer::enable_secured_mode). This adapter signs no
    // test-system packets (receiving-side cases are not wired), so enabling only takes
    // the enforcement flag for the verification of IUT transmissions and succeeds when
    // the named certificate exists in the loaded pool; disabling restores the port
    // parameter default. The SUT's own profile is fixed at process start (VIDF_SUT_ARGS).
    using LibItsCommon__TypesAndValues::AcSecPrimitive;
    bool ok = true;
    if (primitive.get_selection() == AcSecPrimitive::ALT_acEnableSecurity) {
        OCTETSTRING certificate;
        ok = security_services_its::get_instance().read_certificate(primitive.acEnableSecurity().certificateId(), certificate) == 0;
        if (ok) security_checks = primitive.acEnableSecurity().enforceSecurity();
    } else {
        security_checks = security_checks_default;
    }
    LibItsCommon__TypesAndValues::AdapterControlResults results;
    results.acSecResponse() = ok;
    incoming_message(results);
}

} // namespace LibItsGeoNetworking__TestSystem

namespace LibItsCam__TestSystem {
using namespace LibItsCam__TypesAndValues;
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
void UpperTesterPort::outgoing_send(const UtCamInitialize&) {
    UtCamResults result; result.utCamInitializeResult() = true; incoming_message(result); // carrier already running
}
void UpperTesterPort::outgoing_send(const UtCamChangePosition&) {
    UtCamResults result; result.utCamChangePositionResult() = false; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtCamChangePseudonym&) {
    UtCamResults result; result.utCamChangePseudonymResult() = false; incoming_message(result); // no CA service
}
void UpperTesterPort::outgoing_send(const UtCamTrigger&) {
    UtCamResults result; result.utCamTriggerResult() = false; incoming_message(result); // no CA service
}
void UpperTesterPort::outgoing_send(const UtActivatePositionTime&) {
    UtCamResults result; result.utActivatePositionTimeResult() = false; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtDeactivatePositionTime&) {
    UtCamResults result; result.utDeactivatePositionTimeResult() = false; incoming_message(result);
}
} // namespace LibItsCam__TestSystem

namespace LibItsDenm__TestSystem {
using namespace LibItsDenm__TypesAndValues;
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
void UpperTesterPort::outgoing_send(const UtDenmInitialize&) {
    UtDenmResults result; result.utDenmInitializeResult() = true; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtDenmTrigger&) {
    // One syntactically valid DENM carrier per trigger (TS 103 097 clause 7.1.2 profile under
    // test); the situation/validity of the trigger is not acted upon: no DEN service.
    try {
        // Deferred to the next clock advance: the transmission must reach the GN port of
        // the component that drives the clock, not this trigger component.
        const unsigned sequence = ++denm_sequence;
        const bool ok = transact({8, 1, static_cast<unsigned char>(sequence >> 8), static_cast<unsigned char>(sequence)});
        UtDenmResults result;
        result.utDenmTriggerResult().result() = ok;
        result.utDenmTriggerResult().actionId().originatingStationId() = 42;
        result.utDenmTriggerResult().actionId().sequenceNumber() = sequence;
        incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT DENM carrier: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtDenmUpdate&) {
    UtDenmResults result; result.utDenmUpdateResult().result() = false; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtDenmTermination&) {
    // A carrier DENM is sent once and never repeated, so there is nothing left to terminate.
    UtDenmResults result; result.utDenmTerminationResult() = true; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtDenmChangePosition&) {
    UtDenmResults result; result.utDenmChangePositionResult() = false; incoming_message(result);
}
void UpperTesterPort::outgoing_send(const UtDenmChangePseudonym&) {
    UtDenmResults result; result.utDenmChangePseudonymResult() = false; incoming_message(result);
}
} // namespace LibItsDenm__TestSystem
