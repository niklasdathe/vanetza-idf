#include "check.hpp"
#include <vanetza_idf/its_time.hpp>
#include <vanetza/common/clock.hpp>
#include <chrono>

using vidf_test::check;
using namespace vanetza_idf::its_time;

namespace {
// Unix seconds of a UTC calendar instant (days since 1970-01-01, proleptic Gregorian).
constexpr std::int64_t unix_utc(int y, int m, int d, int hh = 0, int mm = 0, int ss = 0) {
    // Howard Hinnant's days_from_civil
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t yoe = y - era * 400;
    const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + doe - 719468;
    return days * 86400 + hh * 3600 + mm * 60 + ss;
}
std::chrono::system_clock::time_point at(std::int64_t unix_seconds, std::int64_t micro = 0) {
    return std::chrono::system_clock::time_point(std::chrono::seconds(unix_seconds) + std::chrono::microseconds(micro));
}
}

void test_its_time() {
    vidf_test::section("test_its_time");
    static_assert(unix_utc(2004, 1, 1) == epoch_unix_seconds, "ITS epoch");
    static_assert(unix_utc(2006, 1, 1) == leap_second_unix_seconds[0], "leap 2005-12-31");
    static_assert(unix_utc(2009, 1, 1) == leap_second_unix_seconds[1], "leap 2008-12-31");
    static_assert(unix_utc(2012, 7, 1) == leap_second_unix_seconds[2], "leap 2012-06-30");
    static_assert(unix_utc(2015, 7, 1) == leap_second_unix_seconds[3], "leap 2015-06-30");
    static_assert(unix_utc(2017, 1, 1) == leap_second_unix_seconds[4], "leap 2016-12-31");

    check(microseconds_since_epoch(epoch_unix_seconds) == 0, "the ITS epoch is zero");
    // TS 102 894-2 V2.4.1 DE_TimestampIts example: 2007-01-01T00:00:00.000Z is 94 694 401 000 ms
    // (one leap second inserted since the epoch).
    check(timestamp_its(at(unix_utc(2007, 1, 1))) == 94694401000ULL, "CDD example: 2007-01-01 = 94 694 401 000 ms");
    // TS 102 894-2: "As of 1 January, 2022, TimestampIts is 5 seconds ahead of UTC".
    check(timestamp_its(at(unix_utc(2022, 1, 1))) == (unix_utc(2022, 1, 1) - epoch_unix_seconds + 5) * 1000ULL,
          "CDD statement: 5 s ahead of UTC since 2017");
    check(time32(at(unix_utc(2022, 1, 1))) == unix_utc(2022, 1, 1) - epoch_unix_seconds + 5, "Time32 uses the same scale in seconds");
    // Around the last insertion: UTC 2016-12-31T23:59:59 and 2017-01-01T00:00:00 are two TAI seconds apart.
    const auto before = since_epoch(at(unix_utc(2016, 12, 31, 23, 59, 59)));
    const auto after = since_epoch(at(unix_utc(2017, 1, 1)));
    check(after - before == std::chrono::seconds(2), "the inserted second (23:59:60) lies between the two UTC seconds");
    // Sub-second parts pass through.
    check(since_epoch(at(unix_utc(2022, 1, 1), 123456)).count() % 1000000 == 123456, "microseconds are kept");
    // Round trips, including instants on either side of every leap second.
    for (auto leap : leap_second_unix_seconds) {
        for (std::int64_t delta : {-2, -1, 0, 1, 2}) {
            const auto expected = (leap + delta) * 1000000 + 500000;
            check(unix_microseconds(microseconds_since_epoch(leap + delta, 500000)) == expected, "Unix round trip around a leap second");
        }
    }
    // The inserted second itself maps onto the following UTC second.
    const auto inserted = microseconds_since_epoch(leap_second_unix_seconds[4]) - 1000000;
    check(unix_microseconds(inserted) == leap_second_unix_seconds[4] * 1000000, "23:59:60 maps onto 00:00:00");
    // vanetza::Clock::time_point carries these microseconds directly; upstream Clock::at() lacks
    // the leap seconds (documented in its_time.hpp), so the helper is the conversion to use.
    const vanetza::Clock::time_point clock {since_epoch(at(unix_utc(2022, 1, 1)))};
    const auto posix = vanetza::Clock::at("2022-01-01 00:00:00");
    check(clock - posix == std::chrono::seconds(5), "upstream Clock::at() is 5 s behind TAI since 2017");
}
