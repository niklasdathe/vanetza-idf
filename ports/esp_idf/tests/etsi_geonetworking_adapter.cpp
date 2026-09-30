// External TITAN SUT adapter for the official AtsGeoNetworking port interfaces.
// Testcase sources and verdict logic are unchanged. This adapter invokes a
// separate host SUT process (vidf_sut) and decodes its actual boundary outputs
// using the ATS's own generated codec (fx_enc/fx_dec), not a hand-rolled parser.
//
// One IUT, many test components: TITAN's parallel runtime forks the MTC and every PTC
// from the host controller, and the multi-node configurations (CF02..CF04) observe the
// IUT from several components at once, as on a shared radio channel. So:
//  - one SUT process is started in the host controller before any fork; its pipes are
//    inherited by every component and a process-shared robust mutex keeps each
//    command/reply exchange atomic (as in etsi_security_adapter.cpp);
//  - everything the SUT reports (transmissions = AL_DATA.request, what it passes up =
//    BTP/GN-DATA.indication) goes into a shared ring; every component delivers the new
//    entries to its own GeoNetworking port (transmissions) and upper tester port
//    (UtGnEventInd), so each simulated neighbour sees the same traffic;
//  - every component advances the SUT's ITS clock to wall-clock ITS time every 10 ms, so
//    router timers (beacons, packet lifetimes, CBF, location-table expiry) run, and a
//    transmission is observed at most 10 ms after the IUT sent it (the timer tests
//    allow 750 ms of beacon jitter; a 100 ms tick could push a correct beacon past it).
//
// Scope: SHB and GBC sources (vanetza rejects GUC/GAC/TSB requests: PICS false),
// receiving side for every packet type the router handles, relative position changes
// (UtGnChangePosition). No GNSS scenarios (PX_GNSS_SCENARIO_SUPPORT false).
#include "UpperTesterPort_GN.hh"
#include "GeoNetworkingPort.hh"
#include "AdapterControlPort_GN.hh"
#include "LibItsGeoNetworking_EncdecDeclarations.hh"
#include "LibItsGeoNetworking_Pixits.hh"
#include "LibItsGeoNetworking_Pics.hh"
#include <vanetza_idf/its_time.hpp>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#include <array>
#include <optional>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

namespace {
using Bytes = std::vector<unsigned char>;
using namespace LibItsGeoNetworking__TypesAndValues;
std::function<void(const GeoNetworkingInd&)> lower_indication;
std::function<void(const UtGnEventInd&)> upper_indication;
unsigned read16(const Bytes& b, unsigned i) { return (b.at(i) << 8) | b.at(i + 1); }

// ITS time (TAI microseconds since 2004-01-01T00:00:00Z), the library's tested conversion.
std::uint64_t its_now_us() {
    return static_cast<std::uint64_t>(vanetza_idf::its_time::since_epoch(std::chrono::system_clock::now()).count());
}

constexpr std::int32_t default_latitude = 520000000;  // Sut::reset(): 52.0N, 13.0E (1/10 microdegree)
constexpr std::int32_t default_longitude = 130000000;

// Shared between all components (MAP_SHARED before the fork).
struct Shared {
    static constexpr unsigned slots = 256, slot_bytes = 2048;
    pthread_mutex_t lock;
    std::uint64_t next;            // sequence number of the next record
    std::int32_t latitude, longitude;
    struct Slot { std::uint64_t sequence; std::uint8_t kind; std::uint16_t size; unsigned char data[slot_bytes]; } ring[slots];
};
Shared* shared = nullptr;

// The IUT's GN_ADDR as the IUT reports it (SUT command 12, record kind 5), refreshed on every
// getLongPosVector: a board configured as a cyclist, a manually configured address or one DAD
// replaced all differ from vanetza::geonet::Address's defaults, which are the fallback.
Bytes reported_gn_addr;

struct Guard {
    pthread_mutex_t* lock;
    explicit Guard(pthread_mutex_t* l) : lock(l) {
        if (pthread_mutex_lock(lock) == EOWNERDEAD) pthread_mutex_consistent(lock); // a component died mid-exchange
    }
    ~Guard() { pthread_mutex_unlock(lock); }
};

class Process {
    pid_t pid_ = -1, owner_ = -1;
    int input_ = -1, output_ = -1;
    pthread_mutex_t* lock_ = nullptr;
public:
    Process() {
        void* memory = mmap(nullptr, sizeof(Shared) + sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) return;
        shared = static_cast<Shared*>(memory);
        lock_ = reinterpret_cast<pthread_mutex_t*>(static_cast<char*>(memory) + sizeof(Shared));
        pthread_mutexattr_t attributes;
        pthread_mutexattr_init(&attributes);
        pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(lock_, &attributes);
        pthread_mutex_init(&shared->lock, &attributes);
        pthread_mutexattr_destroy(&attributes);
        shared->next = 0;
        shared->latitude = default_latitude;
        shared->longitude = default_longitude;
        const char* executable = std::getenv("VIDF_SUT_EXECUTABLE");
        if (!executable) return; // reported on first use
        // VIDF_SUT_ARGS: space separated arguments, e.g. "--beaconing"
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
        Guard guard(lock_);
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

// Next ring record this component has not delivered yet (per process).
std::uint64_t seen = 0;
bool seen_initialised = false;

// Link-layer identity of the simulated node(s) this component plays: the MID of the source GN_ADDR
// of every packet it sends (the ITS-G5 MAC address of a station is its MID, TS 103 836-4-1
// clause 6.3). A unicast transmission of the IUT is delivered only to the node it is addressed to.
using Mac = std::array<unsigned char, 6>;
std::vector<Mac> my_macs;
// AcStartPassBeaconing / AcStopPassBeaconing of this component: deliver the IUT's beacons or filter them
bool pass_beacons = false;
const Mac broadcast_mac {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const Mac default_lower_tester_mac {0x02, 0, 0, 0, 0, 2};

// Source MID of an unsecured GN PDU (Basic 4 + Common 8 octets, then the extended header: SHB and
// beacon start with the SO PV, GUC/GBC/GAC/TSB/LS with 4 octets of SN + reserved before it;
// TS 103 836-4-1 clauses 9.6-9.8). Secured or unknown packets keep the default lower-tester MAC.
Mac source_mac(const unsigned char* pdu, std::size_t size) {
    if (size < 12 || (pdu[0] & 0x0f) != 1) return default_lower_tester_mac; // next header must be the common header
    const unsigned ht = pdu[5] >> 4, hst = pdu[5] & 0x0f;
    const std::size_t pv = (ht == 1 || (ht == 5 && hst == 0)) ? 12 : 16;
    if (size < pv + 8) return default_lower_tester_mac;
    Mac mac;
    std::copy(pdu + pv + 2, pdu + pv + 8, mac.begin());
    return mac;
}
void remember(const Mac& mac) {
    if (std::find(my_macs.begin(), my_macs.end(), mac) == my_macs.end()) my_macs.push_back(mac);
}
// The node this component plays, as the test system defines it: components are created with the names
// NodeA..NodeF (LibItsGeoNetworking_TypesAndValues c_compNodeX) and each node's GN address is the PIXIT
// PX_TS_NODE_X_LOCAL_GN_ADDR; the node's MAC is that address's MID. Empty for the MTC or other names.
std::optional<Mac> node_mac() {
    const char* name = TTCN_Runtime::get_component_name();
    if (!name || std::strncmp(name, "Node", 4) != 0 || !name[4] || name[5]) return std::nullopt;
    using namespace LibItsGeoNetworking__Pixits;
    const GN__Address* address = nullptr;
    switch (name[4]) {
        case 'A': address = &PX__TS__NODE__A__LOCAL__GN__ADDR; break;
        case 'B': address = &PX__TS__NODE__B__LOCAL__GN__ADDR; break;
        case 'C': address = &PX__TS__NODE__C__LOCAL__GN__ADDR; break;
        case 'D': address = &PX__TS__NODE__D__LOCAL__GN__ADDR; break;
        case 'E': address = &PX__TS__NODE__E__LOCAL__GN__ADDR; break;
        case 'F': address = &PX__TS__NODE__F__LOCAL__GN__ADDR; break;
        default: return std::nullopt;
    }
    const OCTETSTRING& mid = address->mid();
    if (mid.lengthof() != 6) return std::nullopt;
    Mac mac;
    std::copy(static_cast<const unsigned char*>(mid), static_cast<const unsigned char*>(mid) + 6, mac.begin());
    return mac;
}
// Link-layer sender of a packet this component transmits: its node's MAC (so a relayed packet keeps the
// relaying node as sender, and a node that never sent anything before is an unknown sender to the IUT);
// outside a node component, the packet's source MID.
Mac sender_mac(const unsigned char* pdu, std::size_t size) {
    const Mac mac = node_mac().value_or(source_mac(pdu, size));
    remember(mac);
    return mac;
}

void publish(std::uint8_t kind, const Bytes& b) {
    if (b.size() > Shared::slot_bytes) { TTCN_warning("SUT record of %zu bytes dropped (ring slot)", b.size()); return; }
    Guard guard(&shared->lock);
    auto& slot = shared->ring[shared->next % Shared::slots];
    slot.sequence = shared->next;
    slot.kind = kind;
    slot.size = static_cast<std::uint16_t>(b.size());
    std::memcpy(slot.data, b.data(), b.size());
    ++shared->next;
}

void deliver_record(std::uint8_t kind, const Bytes& in) {
    Bytes b = in;
    if (kind == 4) {
        // [destination MAC][source MAC][GN PDU]: a component that plays a known node takes only
        // broadcasts and frames addressed to its node (link-layer filtering of a real receiver).
        if (b.size() < 12) return;
        Mac destination;
        std::copy(b.begin(), b.begin() + 6, destination.begin());
        if (destination != broadcast_mac && !my_macs.empty() &&
            std::find(my_macs.begin(), my_macs.end(), destination) == my_macs.end())
            return;
        b.erase(b.begin(), b.begin() + 12);
        kind = 1;
    }
    if (kind == 1 && b.size() > 5 && (b[5] >> 4) == 1 && !pass_beacons) {
        // The IUT's beacons are filtered by the test adapter unless the TP asked for them with
        // AcStartPassBeaconing (as the ETSI framework's geonetworking_layer does in its default mode).
        return;
    }
    if (kind == 1) {
        // AL_DATA transmission of the IUT, decoded with the ATS's own RAW codec.
        if (!lower_indication) return;
        BITSTRING bits = oct2bit(OCTETSTRING(static_cast<int>(b.size()), b.data()));
        GeoNetworkingPdu pdu;
        if (LibItsGeoNetworking__EncdecDeclarations::fx__dec__GeoNetworkingPdu(bits, pdu) != 0) {
            TTCN_warning("IUT transmission not decodable as GeoNetworkingPdu (%zu bytes)", b.size());
            return;
        }
        GeoNetworkingInd indication;
        indication.msgIn() = pdu;
        const unsigned char broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        indication.macDestinationAddress() = OCTETSTRING(6, broadcast);
        indication.ssp() = OMIT_VALUE;
        indication.its__aid() = OMIT_VALUE;
        lower_indication(indication);
    } else if (kind == 2 || kind == 3) {
        // What the IUT passed up: BTP-DATA.indication ([type][dest port][src port/info][SDU]: the GN payload
        // is the 4-octet BTP header plus the SDU, TS 103 836-5-1 clause 7) or a raw GN-DATA.indication.
        if (!upper_indication) return;
        Bytes raw = kind == 2 ? Bytes(b.begin() + 1, b.end()) : b;
        UtGnEventInd event;
        event.rawPayload() = OCTETSTRING(static_cast<int>(raw.size()), raw.data());
        upper_indication(event);
    }
}

// Deliver every record published since this component last looked.
void deliver() {
    if (!shared) return;
    for (;;) {
        std::uint8_t kind = 0;
        Bytes data;
        {
            Guard guard(&shared->lock);
            if (!seen_initialised) { seen = shared->next; seen_initialised = true; }
            if (seen >= shared->next) return;
            if (shared->next - seen > Shared::slots) {
                TTCN_warning("%llu SUT records overwritten before delivery", static_cast<unsigned long long>(shared->next - seen - Shared::slots));
                seen = shared->next - Shared::slots;
            }
            const auto& slot = shared->ring[seen % Shared::slots];
            kind = slot.kind;
            data.assign(slot.data, slot.data + slot.size);
            ++seen;
        }
        deliver_record(kind, data);
    }
}

bool transact(const Bytes& command) {
    const auto reply = sut.exchange(command);
    if (reply.size() < 2) throw std::runtime_error("Truncated SUT response");
    unsigned offset = 2;
    std::vector<std::pair<std::uint8_t, Bytes>> own;
    for (unsigned n = 0; n < reply[1]; ++n) {
        const auto kind = reply.at(offset);
        const auto size = read16(reply, offset + 1);
        offset += 3;
        if (offset + size > reply.size()) throw std::runtime_error("Truncated SUT record");
        if (kind < 1 || kind > 5) throw std::runtime_error("Unexpected SUT record kind");
        Bytes record(reply.begin() + offset, reply.begin() + offset + size);
        if (kind == 5) { reported_gn_addr = std::move(record); offset += size; continue; } // reply to command 12
        // Transmissions are on the shared channel: every component sees them. What the IUT passes up
        // (BTP/GN-DATA.indication) happens synchronously inside this exchange, so it belongs to the component
        // whose stimulus caused it; fanning it out would show one node's legitimate pass-up to another node
        // as a pass-up of its own duplicate (TC_GEONW_PON_TSB_BO_08).
        if (kind == 2 || kind == 3) own.emplace_back(kind, std::move(record));
        else publish(kind, record);
        offset += size;
    }
    if (offset != reply.size()) throw std::runtime_error("Trailing SUT response bytes");
    deliver(); // this component sees its own stimuli' effects at once; the others on their next tick
    for (const auto& [kind, record] : own) deliver_record(kind, record);
    return reply[0] == 0;
}

// One SUT tick: advance the ITS clock to now; transmissions arrive through transact().
void tick() {
    const std::uint64_t now = its_now_us();
    Bytes command {5};
    for (int shift = 56; shift >= 0; shift -= 8) command.push_back(static_cast<unsigned char>(now >> shift));
    transact(command);
}

void push32(Bytes& b, std::int32_t v) {
    b.push_back(static_cast<unsigned>(v) >> 24); b.push_back(static_cast<unsigned>(v) >> 16);
    b.push_back(static_cast<unsigned>(v) >> 8); b.push_back(static_cast<unsigned>(v));
}
void push16(Bytes& b, unsigned v) { b.push_back((v >> 8) & 0xff); b.push_back(v & 0xff); }

unsigned char raw_traffic_class(const TrafficClass& tc) {
    return (tc.scf() == SCF::e__scfEnabled ? 0x80 : 0) | (tc.channelOffload() == ChannelOffload::e__choffEnable ? 0x40 : 0) |
           (static_cast<unsigned>(static_cast<long long>(tc.tcId())) & 0x3f);
}

// GN_Address baked into hil_sut.cpp's Sut::reset() (config.mib.itsGnLocalGnAddr.mid only;
// the other fields stay at vanetza::geonet::Address's defaults). f_acGetLongPosVector's caller
// compares this exactly against the wire source address.
// getLongPosVector reports the IUT's GN_ADDR from reported_gn_addr (see its declaration).
GN__Address iut_gn_address() {
    GN__Address address;
    if (reported_gn_addr.size() == 8) {
        const unsigned first = (reported_gn_addr[0] << 8) | reported_gn_addr[1];
        address.typeOfAddress() = static_cast<TypeOfAddress::enum_type>((first >> 15) & 1);
        address.stationType() = static_cast<StationType::enum_type>((first >> 10) & 0x1f);
        address.reserved() = first & 0x3ff;
        address.mid() = OCTETSTRING(6, reported_gn_addr.data() + 2);
        return address;
    }
    address.typeOfAddress() = TypeOfAddress::e__initial; // Address::m_manually_configured == false
    address.stationType() = StationType::e__unknown;     // Address::m_station_type == StationType::Unknown
    address.reserved() = 0;                              // Address::m_country_code == 0
    const unsigned char mid[] = {2, 0, 0, 0, 0, 1};
    address.mid() = OCTETSTRING(6, mid);
    return address;
}
// The IUT's current position (reset: 52.0N 13.0E, moved by UtGnChangePosition), stationary.
LongPosVector iut_position() {
    LongPosVector position;
    position.gnAddr() = iut_gn_address();
    position.timestamp__() = 0;
    {
        Guard guard(&shared->lock);
        position.latitude() = shared->latitude;
        position.longitude() = shared->longitude;
    }
    const unsigned char zero_bit = 0;
    position.pai() = BITSTRING(1, &zero_bit);
    position.speed() = 0;
    position.heading() = 0;
    return position;
}

// Per-process clock timer, owned by whichever port of this component maps first.
int timer_fd = -1;
const void* timer_owner = nullptr;

// Create the timer if this component has none; true when the calling port shall register it.
bool create_timer(const void* port) {
    if (timer_fd >= 0) return false;
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) TTCN_error("timerfd_create failed");
    itimerspec period {};
    period.it_interval.tv_nsec = 10 * 1000 * 1000;
    period.it_value.tv_nsec = 10 * 1000 * 1000;
    timerfd_settime(timer_fd, 0, &period, nullptr);
    timer_owner = port;
    return true;
}
// Lower-tester beaconing of this component (AcStartBeaconing): the test adapter keeps sending the node's
// beacon every PICS_GN_BEACON_SERVICE_RETRANSMIT_TIMER ms with a current timestamp until AcStopBeaconing.
// A single beacon is not enough: the IUT flushes its forwarding buffers when a packet arrives, before that
// packet updates the location table (TS 103 836-4-1 clause 10.3.3/10.3.5 order), so buffered packets reach
// a new neighbour with its *next* beacon (TC_GEONW_CAP_FPB_BV_02).
std::optional<GeoNetworkingPdu> beacon_pdu;
std::uint64_t next_beacon_us = 0;

void inject(GeoNetworkingPdu pdu, bool refresh_beacon_time) {
    if (refresh_beacon_time && pdu.gnPacket().packet().extendedHeader().ispresent() &&
        pdu.gnPacket().packet().extendedHeader()().ischosen(ExtendedHeader::ALT_beaconHeader)) {
        INTEGER timestamp;
        timestamp.set_long_long_val(static_cast<long long>((its_now_us() / 1000) & 0xffffffffULL));
        pdu.gnPacket().packet().extendedHeader()().beaconHeader().srcPosVector().timestamp__() = timestamp;
    }
    const BITSTRING encoded = LibItsGeoNetworking__EncdecDeclarations::fx__enc__GeoNetworkingPdu(pdu);
    const OCTETSTRING raw = bit2oct(encoded);
    const unsigned char* raw_bytes = raw;
    const Mac source = sender_mac(raw_bytes, raw.lengthof());
    Bytes command {2};
    command.insert(command.end(), source.begin(), source.end());
    command.insert(command.end(), broadcast_mac.begin(), broadcast_mac.end());
    command.insert(command.end(), raw_bytes, raw_bytes + raw.lengthof());
    transact(command);
}

void beacon_if_due() {
    if (!beacon_pdu) return;
    const std::uint64_t now = its_now_us();
    if (now < next_beacon_us) return;
    const auto period_ms = static_cast<std::uint64_t>(static_cast<long long>(LibItsGeoNetworking__Pics::PICS__GN__BEACON__SERVICE__RETRANSMIT__TIMER));
    next_beacon_us = now + period_ms * 1000;
    inject(*beacon_pdu, true);
}

void on_timer(int fd) {
    if (fd != timer_fd) return;
    std::uint64_t expirations = 0;
    if (read(timer_fd, &expirations, sizeof(expirations)) != sizeof(expirations)) return;
    try { tick(); beacon_if_due(); } catch (const std::exception& e) { TTCN_error("SUT tick: %s", e.what()); }
}
}

namespace LibItsGeoNetworking__TestSystem {

UpperTesterPort::UpperTesterPort(const char* name) : UpperTesterPort_BASE(name) {}
UpperTesterPort::~UpperTesterPort() = default;
void UpperTesterPort::set_parameter(const char*, const char*) {}
void UpperTesterPort::Handle_Fd_Event_Error(int) {}
void UpperTesterPort::Handle_Fd_Event_Writable(int) {}
void UpperTesterPort::Handle_Fd_Event_Readable(int fd) { on_timer(fd); }
void UpperTesterPort::receiveMsg(const Base_Type&, const params&) {}
void UpperTesterPort::user_map(const char*) {
    upper_indication = [this](const UtGnEventInd& event) { incoming_message(event); };
    if (create_timer(this)) Handler_Add_Fd_Read(timer_fd);
}
void UpperTesterPort::user_unmap(const char*) {
    upper_indication = {};
    if (timer_owner == this && timer_fd >= 0) { Handler_Remove_Fd_Read(timer_fd); close(timer_fd); timer_fd = -1; timer_owner = nullptr; }
}
void UpperTesterPort::user_start() {}
void UpperTesterPort::user_stop() {}
void UpperTesterPort::outgoing_send(const UtGnInitialize&) {
    try {
        bool ok = transact({0});
        {
            Guard guard(&shared->lock);
            shared->latitude = default_latitude;
            shared->longitude = default_longitude;
        }
        tick(); // the router runs at ITS time from the start
        UtGnResults result; result.utGnInitializeResult() = ok; incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT initialization: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtGnChangePosition& change) {
    // TS 102 871-2 / LibItsGeoNetworking_TypesAndValues: the values are relative to the current
    // position (1/10 microdegree, the LongPosVector unit).
    try {
        std::int32_t latitude, longitude;
        {
            Guard guard(&shared->lock);
            shared->latitude += static_cast<std::int32_t>(static_cast<long long>(change.latitude()));
            shared->longitude += static_cast<std::int32_t>(static_cast<long long>(change.longitude()));
            latitude = shared->latitude;
            longitude = shared->longitude;
        }
        Bytes command {4};
        push32(command, latitude);
        push32(command, longitude);
        UtGnResults result; result.utGnChangePositionResult() = transact(command); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT position change: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtGnTrigger& trigger) {
    try {
        Bytes command;
        if (trigger.get_selection() == UtGnTrigger::ALT_shb) {
            const auto& shb = trigger.shb();
            command = {3, raw_traffic_class(shb.trafficClass())};
            const OCTETSTRING& payload = shb.payload();
            const unsigned char* ptr = payload;
            command.insert(command.end(), ptr, ptr + payload.lengthof());
        } else if (trigger.get_selection() == UtGnTrigger::ALT_geoBroadcast) {
            const auto& gbc = trigger.geoBroadcast();
            const auto& area = gbc.area();
            command = {10, raw_traffic_class(gbc.trafficClass()), static_cast<unsigned char>(gbc.shape().as_int())};
            push32(command, static_cast<std::int32_t>(static_cast<long long>(area.geoAreaPosLatitude())));
            push32(command, static_cast<std::int32_t>(static_cast<long long>(area.geoAreaPosLongitude())));
            push16(command, static_cast<unsigned>(static_cast<long long>(area.distanceA())));
            push16(command, static_cast<unsigned>(static_cast<long long>(area.distanceB())));
            push16(command, static_cast<unsigned>(static_cast<long long>(area.angle())));
            push16(command, static_cast<unsigned>(static_cast<long long>(gbc.lifetime())));
            const OCTETSTRING& payload = gbc.payload();
            const unsigned char* ptr = payload;
            command.insert(command.end(), ptr, ptr + payload.lengthof());
        } else {
            // GUC/GAC/TSB: the vanetza router rejects these requests (PICS_GN_*_SRC false).
            UtGnResults result; result.utGnTriggerResult() = false; incoming_message(result);
            return;
        }
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
void GeoNetworkingPort::Handle_Fd_Event_Readable(int fd) { on_timer(fd); }
void GeoNetworkingPort::receiveMsg(const GeoNetworkingInd&, const params&) {}
void GeoNetworkingPort::user_map(const char*) {
    lower_indication = [this](const GeoNetworkingInd& p) { incoming_message(p); };
    if (const auto mac = node_mac()) remember(*mac); // unicast frames to this node reach this component
    if (create_timer(this)) Handler_Add_Fd_Read(timer_fd);
}
void GeoNetworkingPort::user_unmap(const char*) {
    lower_indication = {};
    if (timer_owner == this && timer_fd >= 0) { Handler_Remove_Fd_Read(timer_fd); close(timer_fd); timer_fd = -1; timer_owner = nullptr; }
}
void GeoNetworkingPort::user_start() {}
void GeoNetworkingPort::user_stop() {}
void GeoNetworkingPort::outgoing_send(const GeoNetworkingReq& send_par) {
    // The lower tester injecting a packet toward the IUT (a neighbour's SHB/GBC/TSB/beacon):
    // encode via the ATS's own codec, submit as AL_DATA.indication.
    try {
        // Bring the SUT's ITS clock to now first: otherwise the router timestamps the reception up to one tick
        // early and timers derived from it (CBF contention, TS 103 836-4-1 Annex F.3) expire early.
        tick();
        const BITSTRING encoded = LibItsGeoNetworking__EncdecDeclarations::fx__enc__GeoNetworkingPdu(send_par.msgOut());
        const OCTETSTRING raw = bit2oct(encoded);
        const unsigned char* ptr = raw;
        const unsigned char* mac = send_par.macDestinationAddress();
        // the sending node is the one this component plays: its MAC is the MID of the first packet it sent
        // (its beacon); a relayed packet keeps the relaying node as link-layer sender, as on air
        const Mac source = sender_mac(ptr, raw.lengthof());
        Bytes command {2};
        command.insert(command.end(), source.begin(), source.end());
        command.insert(command.end(), mac, mac + 6);
        command.insert(command.end(), ptr, ptr + raw.lengthof());
        if (!transact(command)) TTCN_warning("SUT did not accept the lower tester packet (discarded by the IUT)");
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
    // f_acTriggerEvent (LibItsGeoNetworking_Functions.ttcn) is fire-and-forget for every
    // AcGnPrimitive except getLongPosVector, which f_acGetLongPosVector waits on synchronously.
    if (primitive.get_selection() == AcGnPrimitive::ALT_getLongPosVector) {
        try { transact({12}); } catch (const std::exception& e) { TTCN_error("SUT GN address: %s", e.what()); }
        AcGnResponse response; response.getLongPosVector() = iut_position();
        incoming_message(response);
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_startBeaconing) {
        // f_startBeingNeighbour: this node beacons now and then periodically until stopBeaconing.
        try {
            tick();
            beacon_pdu = primitive.startBeaconing().beaconPacket();
            next_beacon_us = 0;
            beacon_if_due();
        } catch (const std::exception& e) {
            TTCN_warning("startBeaconing: %s", e.what());
        }
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_stopBeaconing) {
        beacon_pdu.reset();
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_startPassBeaconing) {
        pass_beacons = true;
    } else if (primitive.get_selection() == AcGnPrimitive::ALT_stopPassBeaconing) {
        pass_beacons = false;
    }
}
void AdapterControlPort::outgoing_send(const LibItsIpv6OverGeoNetworking__TypesAndValues::AcGn6Primitive&) {}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcGnssPrimitive&) {
    // Only reached if PX_GNSS_SCENARIO_SUPPORT is true; the configuration sets it false.
}
void AdapterControlPort::outgoing_send(const LibItsCommon__TypesAndValues::AcSecPrimitive&) {}

}
