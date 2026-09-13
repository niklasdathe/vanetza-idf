#include "hil_sut.hpp"
#include <cstdio>
#include <iostream>
#include <string>
int main() {
    vidf_test::Sut sut;
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
