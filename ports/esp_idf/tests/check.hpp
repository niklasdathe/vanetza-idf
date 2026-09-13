#pragma once
#include <stdexcept>
#include <string>

// Shared assertion helper of the port regression: one counter across all test
// translation units, failures throw so the first broken check stops the run.
namespace vidf_test {
inline unsigned checks = 0;
inline void check(bool ok, const char* description) {
    ++checks;
    if (!ok) throw std::runtime_error(description);
}
inline std::string hex(const void* data, std::size_t size) {
    std::string result;
    const char* digits = "0123456789abcdef";
    const auto* bytes = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < size; ++i) { result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15]; }
    return result;
}
template<class Container> std::string hex(const Container& bytes) { return hex(bytes.data(), bytes.size()); }
}
