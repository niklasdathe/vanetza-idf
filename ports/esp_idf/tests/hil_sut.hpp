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
 *  0 [digest]   reset (unsecured BTP profile, or the security profile when a pool is configured);
 *               with an ETSI IUT install the optional HashedId8 (8 octets, UtGnInitialize.hashedId8)
 *               names the AT to sign with, all-zero or absent = the profile's default ticket
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
 * 10 tc shape lat lon a b angle lifetime sdu
 *                          GN-DATA.request GBC: raw traffic class, shape (0 circle, 1 rectangle,
 *                          2 ellipse), centre i32 BE (1e-7 degree), distances a/b u16 (m), angle u16
 *                          (degree), lifetime u16 (ms, 0 = default), payload
 * 11 digest                make the AT with this HashedId8 (8 octets) the current one
 *                          (UtDenmChangePseudonym / UtCamChangePseudonym)
 * 12                       report the local GN_ADDR: one kind-5 record with its 8 octets
 * Reply: [result][record count]{[kind][u16 length][bytes]}: kind 1 = AL_DATA.request
 * transmitted, 2 = BTP-DATA.indication, 3 = GN-DATA.indication, 4 = AL_DATA.request with its
 * link-layer addresses ([destination MAC][source MAC][GN PDU], instead of kind 1 with --link-layer),
 * 5 = the local GN_ADDR (reply to 12).
 */
struct SecurityProfile {
    std::string pool;             // directory with <name>.oer (COER certificate) and <name>.vkey (raw private key)
    std::string root = "CERT_IUT_A_RCA";
    // every AA the station trusts as an issuer (its own and, for the receiving-side campaign, the
    // test system's); ATs of other AAs must arrive through P2P certificate distribution
    std::vector<std::string> authorities {"CERT_IUT_A_AA", "CERT_TS_A_AA"};
    std::string ticket = "CERT_IUT_A_AT";
    // ETSI IUT install (itscertgen `make install`, TS.ITS data/certificates): every *_RCA is a root,
    // every *_AA a known authority, every certificate with a .vkey a ticket; replaces root/authorities
    // and makes `ticket` only the default selection
    std::string etsi_install;
    // authorities of the install the IUT must not know (the ATS's "unknown AA" certificates)
    std::vector<std::string> etsi_unknown;
    bool anonymous_address = false; // itsGnLocalAddrConfMethod ANONYMOUS: MID from the ticket digest
};

class Sut final : public vanetza_idf::Access {
public:
    Sut();
    ~Sut();
    /// configure the security profile used by the next reset; empty pool = unsecured
    void configure(SecurityProfile);
    /// beacon service in the unsecured profile (the micrOBU firmware beacons unless told not to);
    /// off by default so the BTP campaign sees only what it triggers
    void beaconing(bool on) { beaconing_ = on; }
    /// report transmissions as kind 4 (with destination/source MAC): lets a multi-node test system
    /// tell a unicast next-hop forward from a broadcast
    void link_layer(bool on) { link_layer_ = on; }
    /// itsGnLocalAddrConfMethod AUTO in the unsecured profile (DAD applies, TS 103 836-4-1 clause 10.2.1.5);
    /// the micrOBU uses AUTO when the phone configures address_configuration 0
    void auto_address(bool on) { auto_address_ = on; }
    /// credentials handed over at run time (diagnostic command 9, a credentials.hpp
    /// bundle): used by the next reset instead of the pool directory; empty = none
    vanetza_idf::Result provision(const vanetza::ByteBuffer& bundle);
    vanetza::ByteBuffer execute(const vanetza::ByteBuffer&);
    vanetza_idf::Result request(vanetza_idf::AlDataRequest) override;
private:
    class Security;
    SecurityProfile profile_;
    vanetza::ByteBuffer bundle_;
    vanetza::ByteBuffer selected_; // HashedId8 of the AT the next reset selects; empty = default
    std::unique_ptr<vanetza::ManualRuntime> runtime_;
    std::unique_ptr<Security> security_;
    std::unique_ptr<vanetza_idf::Stack> stack_;
    std::vector<vanetza::ByteBuffer> records_;
    std::size_t record_bytes_ = 0;
    bool overflow_ = false;
    bool beaconing_ = false;
    bool link_layer_ = false;
    bool auto_address_ = false;
    vanetza::PositionFix fix_;
    long here_latitude() const;  // fix_ in 1e-7 degree (CDD Latitude/Longitude)
    long here_longitude() const;
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
