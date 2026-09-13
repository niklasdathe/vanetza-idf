// External TITAN SUT adapter for the official AtsBTP port interfaces.
// Testcase sources and verdict logic are unchanged. This adapter invokes a
// separate host/device SUT process and decodes its actual boundary outputs.
#include "UpperTesterPort_BTP.hh"
#include "BtpPort.hh"
#include <functional>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <stdexcept>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

namespace {
using Bytes = std::vector<unsigned char>;
using namespace LibItsBtp__TypesAndValues;
std::function<void(const BtpInd&)> lower_indication;
std::function<void(const UtBtpEventInd&)> upper_indication;
unsigned read16(const Bytes& b, unsigned i) { return (b.at(i) << 8) | b.at(i + 1); }
void u16(Bytes& b, unsigned n) { b.push_back(n >> 8); b.push_back(n); }
void u32(Bytes& b, unsigned n) { for (int shift = 24; shift >= 0; shift -= 8) b.push_back(n >> shift); }

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
            // NT1 lower observation: GN Basic/Common/SHB headers precede BTP.
            // No fields are copied from the stimulus to manufacture an output.
            if (b.size() < 44 || (b[0] & 15) != 1 || b[5] != 0x50 ||
                read16(b, 8) != b.size() - 40) throw std::runtime_error("Unexpected lower-layer GN frame");
            BtpInd indication;
            auto& packet = indication.msgIn();
            if ((b[4] >> 4) == 1) {
                packet.header().btpAHeader().destinationPort() = read16(b, 40);
                packet.header().btpAHeader().sourcePort() = read16(b, 42);
            } else if ((b[4] >> 4) == 2) {
                packet.header().btpBHeader().destinationPort() = read16(b, 40);
                packet.header().btpBHeader().destinationPortInfo() = read16(b, 42);
            } else throw std::runtime_error("Unknown BTP upper protocol");
            packet.payload() = OCTETSTRING(b.size() - 44, b.data() + 44);
            if (lower_indication) lower_indication(indication);
        } else if (kind == 2) {
            if (b.size() < 5) throw std::runtime_error("Truncated BTP indication");
            UtBtpEventInd indication;
            indication.rawPayload() = OCTETSTRING(b.size() - 5, b.data() + 5);
            if (upper_indication) upper_indication(indication);
        } else throw std::runtime_error("Unexpected SUT record kind");
    }
    if (offset != reply.size()) throw std::runtime_error("Trailing SUT response bytes");
    return reply[0] == 0;
}
}

namespace LibItsBtp__TestSystem {
UpperTesterPort::UpperTesterPort(const char* name) : UpperTesterPort_BASE(name) {}
UpperTesterPort::~UpperTesterPort() = default;
void UpperTesterPort::set_parameter(const char*, const char*) {}
void UpperTesterPort::Handle_Fd_Event_Error(int) {}
void UpperTesterPort::Handle_Fd_Event_Writable(int) {}
void UpperTesterPort::Handle_Fd_Event_Readable(int) {}
void UpperTesterPort::user_map(const char*) {
    upper_indication = [this](const UtBtpEventInd& p) { incoming_message(p); };
}
void UpperTesterPort::user_unmap(const char*) { upper_indication = {}; }
void UpperTesterPort::user_start() {}
void UpperTesterPort::user_stop() {}
void UpperTesterPort::outgoing_send(const UtBtpInitialize&) {
    try {
        UtBtpResults result; result.utBtpInitializeResult() = transact({0}); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT initialization: %s", e.what()); }
}
void UpperTesterPort::outgoing_send(const UtBtpTrigger& trigger) {
    try {
        Bytes command {1};
        if (trigger.get_selection() == UtBtpTrigger::ALT_btpA) {
            command.push_back(0);
            u16(command, static_cast<int>(trigger.btpA().btpAHeader().destinationPort()));
            u16(command, static_cast<int>(trigger.btpA().btpAHeader().sourcePort()));
        } else {
            command.push_back(1);
            u16(command, static_cast<int>(trigger.btpB().btpBHeader().destinationPort()));
            u16(command, static_cast<int>(trigger.btpB().btpBHeader().destinationPortInfo()));
        }
        command.push_back(0); // unspecified generation payload chosen by test application
        UtBtpResults result; result.utBtpTriggerResult() = transact(command); incoming_message(result);
    } catch (const std::exception& e) { TTCN_error("SUT BTP trigger: %s", e.what()); }
}
BtpPort::BtpPort(const char* name) : BtpPort_BASE(name), _layer(nullptr) {}
BtpPort::~BtpPort() = default;
void BtpPort::set_parameter(const char*, const char*) {}
void BtpPort::Handle_Fd_Event_Error(int) {}
void BtpPort::Handle_Fd_Event_Writable(int) {}
void BtpPort::Handle_Fd_Event_Readable(int) {}
void BtpPort::user_map(const char*) { lower_indication = [this](const BtpInd& p) { incoming_message(p); }; }
void BtpPort::user_unmap(const char*) { lower_indication = {}; }
void BtpPort::user_start() {}
void BtpPort::user_stop() {}
void BtpPort::receiveMsg(const BtpInd& p, const params&) { incoming_message(p); }
void BtpPort::outgoing_send(const BtpReq& request) {
    try {
        const auto& packet = request.msgOut();
        const bool type_b = packet.header().get_selection() == BtpHeader::ALT_btpBHeader;
        Bytes btp;
        if (type_b) {
            u16(btp, static_cast<int>(packet.header().btpBHeader().destinationPort()));
            u16(btp, static_cast<int>(packet.header().btpBHeader().destinationPortInfo()));
        } else {
            u16(btp, static_cast<int>(packet.header().btpAHeader().destinationPort()));
            u16(btp, static_cast<int>(packet.header().btpAHeader().sourcePort()));
        }
        if (packet.payload().ispresent()) {
            const OCTETSTRING& data = packet.payload()();
            const unsigned char* ptr = data;
            btp.insert(btp.end(), ptr, ptr + data.lengthof());
        }
        // Independent lower tester GN SHB carrier (TS 103 836-4-1 headers).
        // Station/position are test PIXIT fixtures; the SUT never generates it.
        Bytes gn {0x11, 0, 0x05, 1, static_cast<unsigned char>(type_b ? 0x20 : 0x10), 0x50, 0, 0x80};
        u16(gn, btp.size()); gn.push_back(1); gn.push_back(0);
        gn.insert(gn.end(), {0, 0, 2, 0, 0, 0, 0, 2});
        u32(gn, 0); u32(gn, 520000000); u32(gn, 130000000);
        u16(gn, 0); u16(gn, 0); u32(gn, 0);
        gn.insert(gn.end(), btp.begin(), btp.end());
        Bytes command {2, 2,0,0,0,0,2, 255,255,255,255,255,255};
        command.insert(command.end(), gn.begin(), gn.end());
        if (!transact(command)) TTCN_error("SUT rejected lower tester submission");
    } catch (const std::exception& e) { TTCN_error("SUT lower tester: %s", e.what()); }
}
}
