#pragma once
#include <vanetza_idf/stack.hpp>
#include <memory>
#include <string>
#include <vector>

namespace vidf_test {
/** Application diagnostic protocol, not an ETSI primitive or verdict codec.
 * An external ETSI SUT adapter translates UT operations to these test points.
 *
 * Commands (first octet):
 *  0            reset (unsecured BTP profile, or the security profile when a pool is configured)
 *  1 t port info/src sdu   BTP-DATA.request
 *  2 src dst gnpdu         AL_DATA.indication from the lower tester
 *  3 tc sdu                GN-DATA.request (SHB)
 *  4 lat lon               position fix (1e-7 degree, i32 BE)
 *  5 time                  advance the ITS clock to the given microseconds since 2004-01-01 (u64 BE);
 *                          spontaneous transmissions (beacons) are reported in the reply
 *  6 kind [seq u16]        carrier stimulus: send a syntactically valid CAM (0) or DENM (1, actionId
 *                          sequence number seq) through facilities::send; test-application behaviour,
 *                          not a CA/DEN service
 *  7 kind interval u16     periodic carrier every interval ms on ticks (0 = stop)
 *  8 kind [seq u16]        as 6, but sent with the next clock advance (5) so the transmission is
 *                          reported to whoever drives the clock, not to the caller
 * Reply: [result][record count]{[kind][u16 length][bytes]}: kind 1 = AL_DATA.request
 * transmitted, 2 = BTP-DATA.indication, 3 = GN-DATA.indication.
 */
struct SecurityProfile {
    std::string pool;             // directory with <name>.oer (COER certificate) and <name>.vkey (raw private key)
    std::string root = "CERT_IUT_A_RCA";
    // every AA the station trusts as an issuer (its own and, for the receiving-side campaign, the
    // test system's); ATs of other AAs must arrive through P2P certificate distribution
    std::vector<std::string> authorities {"CERT_IUT_A_AA", "CERT_TS_A_AA"};
    std::string ticket = "CERT_IUT_A_AT";
    bool anonymous_address = false; // itsGnLocalAddrConfMethod ANONYMOUS: MID from the ticket digest
};

class Sut final : public vanetza_idf::Access {
public:
    Sut();
    ~Sut();
    /// configure the security profile used by the next reset; empty pool = unsecured
    void configure(SecurityProfile);
    vanetza::ByteBuffer execute(const vanetza::ByteBuffer&);
    vanetza_idf::Result request(vanetza_idf::AlDataRequest) override;
private:
    class Security;
    SecurityProfile profile_;
    std::unique_ptr<vanetza::ManualRuntime> runtime_;
    std::unique_ptr<Security> security_;
    std::unique_ptr<vanetza_idf::Stack> stack_;
    std::vector<vanetza::ByteBuffer> records_;
    std::size_t record_bytes_ = 0;
    bool overflow_ = false;
    vanetza::PositionFix fix_;
    std::uint16_t carrier_interval_[2] = {0, 0};
    vanetza::Clock::time_point carrier_next_[2];
    bool carrier_pending_[2] = {false, false};
    std::uint16_t carrier_pending_sequence_[2] = {0, 0};
    std::uint16_t denm_sequence_ = 0;
    void record(std::uint8_t, vanetza::ByteBuffer);
    vanetza_idf::Result reset();
    vanetza_idf::Result position(double latitude, double longitude);
    vanetza_idf::Result carrier(std::uint8_t kind, std::uint16_t sequence);
};
}
