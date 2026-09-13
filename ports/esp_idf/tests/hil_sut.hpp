#pragma once
#include <vanetza_idf/stack.hpp>
#include <vector>

namespace vidf_test {
// Application diagnostic protocol, not an ETSI primitive or verdict codec.
// An external ETSI SUT adapter translates UT operations to these test points.
class Sut final : public vanetza_idf::Access {
public:
    vanetza::ByteBuffer execute(const vanetza::ByteBuffer&);
    vanetza_idf::Result request(vanetza_idf::AlDataRequest) override;
private:
    std::unique_ptr<vanetza::ManualRuntime> runtime_;
    std::unique_ptr<vanetza_idf::Stack> stack_;
    std::vector<vanetza::ByteBuffer> records_;
    std::size_t record_bytes_ = 0;
    bool overflow_ = false;
    void record(std::uint8_t, vanetza::ByteBuffer);
    vanetza_idf::Result reset();
};
}
