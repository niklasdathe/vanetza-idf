#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/cbr_aggregator.hpp>
#include <vanetza/geonet/location_table.hpp>
#include <vanetza/geonet/loctex_g5.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/net/mac_address.hpp>

using namespace vanetza;
using namespace vanetza::geonet;
using vanetza::dcc::ChannelLoad;
using std::chrono::seconds;

class CbrAggregatorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        mib.reset(new MIB());
        runtime.reset(new ManualRuntime(Clock::at("2017-05-20 17:36:00")));
        location_table.reset(new LocationTable(*mib, *runtime));
    }

    void TearDown() override
    {
        location_table.reset();
        runtime.reset();
        mib.reset();
    }

    Timestamp timestamp_earlier(std::chrono::milliseconds ms)
    {
        Timestamp ts { runtime->now() };
        ts -= Timestamp::duration_type { ms.count() * Timestamp::millisecond() };
        return ts;
    }

    Address address(unsigned i)
    {
        Address addr;
        addr.mid(create_mac_address(i));
        return addr;
    }

    std::unique_ptr<LocTEX_G5> loctex_g5(Clock::duration age, double local, double one_hop)
    {
        std::unique_ptr<LocTEX_G5> entry { new LocTEX_G5() };
        entry->local_update = Timestamp { runtime->now() - age };
        entry->dcc_mco.local_cbr(ChannelLoad (local));
        entry->dcc_mco.neighbour_cbr(ChannelLoad (one_hop));
        return entry;
    }

    std::unique_ptr<Runtime> runtime;
    std::unique_ptr<MIB> mib;
    std::unique_ptr<LocationTable> location_table;
};

TEST_F(CbrAggregatorTest, init)
{
    CbrAggregator cbra;
    EXPECT_EQ(ChannelLoad(0.0), cbra.get_local_cbr());
    EXPECT_EQ(ChannelLoad(0.0), cbra.get_one_hop_cbr());
    EXPECT_EQ(ChannelLoad(0.0), cbra.get_two_hop_cbr());
    EXPECT_EQ(ChannelLoad(0.0), cbra.get_global_cbr());
}

TEST_F(CbrAggregatorTest, local_cbr)
{
    CbrAggregator cbra;
    ChannelLoad cbr_target(0.6);
    cbra.aggregate(ChannelLoad(0.1), *location_table, timestamp_earlier(seconds(5)), cbr_target);
    EXPECT_EQ(ChannelLoad(0.1), cbra.get_local_cbr());
    cbra.aggregate(ChannelLoad(0.2), *location_table, timestamp_earlier(seconds(5)), cbr_target);
    EXPECT_EQ(ChannelLoad(0.2), cbra.get_local_cbr());

    // no one-hop and two-hop values have been provided: previous local measurement should be maximum
    EXPECT_EQ(ChannelLoad(0.1), cbra.get_global_cbr());
}

TEST_F(CbrAggregatorTest, shared_cbr)
{
    location_table->get_or_create_entry(address(1)).extensions.insert(loctex_g5(seconds(3), 0.45, 0.5));
    location_table->get_or_create_entry(address(2)).extensions.insert(loctex_g5(seconds(2), 0.4, 0.2));
    location_table->get_or_create_entry(address(3)).extensions.insert(loctex_g5(seconds(4), 0.4, 0.45));
    location_table->get_or_create_entry(address(4)).extensions.insert(loctex_g5(seconds(2), 0.35, 0.25));

    CbrAggregator cbra;
    cbra.aggregate(ChannelLoad(0.32), *location_table, timestamp_earlier(seconds(10)), ChannelLoad(0.6));
    EXPECT_DOUBLE_EQ(0.32, cbra.get_local_cbr().value());
    EXPECT_NEAR(0.4, cbra.get_one_hop_cbr().value(), 0.005); // second largest (one hop average = 0.4 < target = 0.6)
    EXPECT_NEAR(0.45, cbra.get_two_hop_cbr().value(), 0.005); // second largest (two hop average = 0.35 < target = 0.6)
    EXPECT_NEAR(0.45, cbra.get_global_cbr().value(), 0.005);

    cbra.aggregate(ChannelLoad(0.34), *location_table, timestamp_earlier(seconds(10)), ChannelLoad(0.3));
    EXPECT_DOUBLE_EQ(0.34, cbra.get_local_cbr().value());
    EXPECT_NEAR(0.45, cbra.get_one_hop_cbr().value(), 0.005); // largest (two hop average above target)
    EXPECT_NEAR(0.5, cbra.get_two_hop_cbr().value(), 0.005); // largest (two hop average above target)
    EXPECT_NEAR(0.5, cbra.get_global_cbr().value(), 0.005);

    cbra.aggregate(ChannelLoad(0.3), *location_table, timestamp_earlier(seconds(2)), ChannelLoad(0.3));
    EXPECT_DOUBLE_EQ(0.3, cbra.get_local_cbr().value());
    EXPECT_NEAR(0.4, cbra.get_one_hop_cbr().value(), 0.005); // average (0.375) above target: largest
    EXPECT_NEAR(0.2, cbra.get_two_hop_cbr().value(), 0.005); // average (0.225) below target: second largest
    EXPECT_NEAR(0.4, cbra.get_global_cbr().value(), 0.005);
}

// TEST-DCC-R2-NET-001 expiry vector / EXT-ETSI-TS103836-4-2-C5-3-GCBR: "Received CBR values
// expire after 1 000 ms". Regression coverage for the DCC_NET wiring in
// implementation/external/vanetza-idf/ports/esp_idf/src/stack.cpp, which calls
// aggregate(..., now - 1000ms, ...) itself (deliberately not the vendored
// DccInformationSharing convenience wrapper, whose own trigger() instead passes its previous
// ~100 ms poll time as the cutoff -- too strict for neighbours whose own VAM cadence can be up
// to T_GenVamMax = 5000 ms). This exercises exactly that cutoff computation via CbrAggregator's
// own public contract, independent of which caller supplies it.
TEST_F(CbrAggregatorTest, expiry_boundary)
{
    constexpr auto lifetime = std::chrono::milliseconds(1000);
    location_table->get_or_create_entry(address(1)).extensions.insert(loctex_g5(std::chrono::milliseconds(999), 0.8, 0.8));
    location_table->get_or_create_entry(address(2)).extensions.insert(loctex_g5(std::chrono::milliseconds(1001), 0.8, 0.8));

    CbrAggregator cbra;
    const Timestamp cutoff { runtime->now() - lifetime };
    cbra.aggregate(ChannelLoad(0.1), *location_table, cutoff, ChannelLoad(0.6));
    EXPECT_NEAR(0.8, cbra.get_one_hop_cbr().value(), 0.005) << "a 999 ms old neighbour is still within the 1 000 ms lifetime";
    EXPECT_NEAR(0.8, cbra.get_global_cbr().value(), 0.005);
}

TEST_F(CbrAggregatorTest, expiry_drops_stale_entries)
{
    constexpr auto lifetime = std::chrono::milliseconds(1000);
    location_table->get_or_create_entry(address(1)).extensions.insert(loctex_g5(std::chrono::milliseconds(1001), 0.8, 0.8));

    CbrAggregator cbra;
    const Timestamp cutoff { runtime->now() - lifetime };
    cbra.aggregate(ChannelLoad(0.1), *location_table, cutoff, ChannelLoad(0.6));
    EXPECT_DOUBLE_EQ(0.0, cbra.get_one_hop_cbr().value()) << "a 1 001 ms old neighbour must not contribute";
    // global_cbr is max(previous local, one_hop, two_hop) -- on this aggregator's first-ever
    // call there is no previous local measurement yet (default 0.0), only the current one (0.1),
    // so with the stale neighbour dropped, global correctly stays at 0.0, not 0.1.
    EXPECT_DOUBLE_EQ(0.0, cbra.get_global_cbr().value()) << "no previous local measurement and no valid neighbour yet";
}
