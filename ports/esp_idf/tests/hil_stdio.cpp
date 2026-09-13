// Host SUT process: one hex command line in, one hex reply line out.
//   vidf_sut [--security-pool DIR [--root NAME] [--aa NAME] [--at NAME] [--anonymous]]
// With a pool the reset command builds the secured, beaconing profile from
// DIR/<NAME>.oer and DIR/<at NAME>.vkey (the layout the ETSI ATS certificate
// loader uses as well); without one the unsecured BTP/GN profile is used.
#include "hil_sut.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
int main(int argc, char** argv) {
    vidf_test::Sut sut;
    vidf_test::SecurityProfile profile;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool has_value = i + 1 < argc;
        if (arg == "--security-pool" && has_value) profile.pool = argv[++i];
        else if (arg == "--root" && has_value) profile.root = argv[++i];
        else if (arg == "--aa" && has_value) profile.authority = argv[++i];
        else if (arg == "--at" && has_value) profile.ticket = argv[++i];
        else if (arg == "--anonymous") profile.anonymous_address = true;
        else { std::fprintf(stderr, "unknown argument: %s\n", arg.c_str()); return 2; }
    }
    sut.configure(profile);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.size() > 8192 || line.size() % 2) return 2;
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        vanetza::ByteBuffer input;
        for (std::size_t i = 0; i < line.size(); i += 2) {
            const int a = nibble(line[i]), b = nibble(line[i + 1]);
            if (a < 0 || b < 0) return 2;
            input.push_back((a << 4) | b);
        }
        for (auto byte : sut.execute(input)) std::printf("%02x", byte);
        std::puts(""); std::fflush(stdout);
    }
}
