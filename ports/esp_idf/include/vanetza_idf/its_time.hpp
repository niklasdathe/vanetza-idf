#pragma once
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

/** ITS time base: TAI microseconds since the ITS epoch 2004-01-01T00:00:00.000 UTC.
 *
 * TS 102 894-2 V2.4.1 DE_TimestampIts: "elapsed milliseconds since the ITS epoch
 * ... TAI is a continuous time scale. UTC has discontinuities, as it is occasionally
 * adjusted by leap seconds. As of 1 January, 2022, TimestampIts is 5 seconds ahead
 * of UTC" (example: 2007-01-01T00:00:00.000Z is 94 694 401 000 ms, one leap second
 * since the epoch). IEEE Std 1609.2 Time64 is the same scale in microseconds and
 * Time32 in seconds ("the number of (TAI) microseconds/seconds since 00:00:00 UTC,
 * 1 January, 2004", Ieee1609Dot2BaseTypes ASN.1 module as published by ETSI);
 * TS 103 097 V2.2.1 generationTime and certificate validityPeriod use them. vanetza::Clock::time_point counts these
 * microseconds; upstream's Clock::at(posix_time) subtracts the epoch in UTC without
 * leap seconds and is therefore 5 s behind since 2017: convert wall-clock time with
 * this header.
 *
 * Leap seconds are announced by the IERS at most six months ahead; the table ends
 * with the insertion of 2016-12-31 (Bulletin C 52). It must be extended when a new
 * one is announced, the same as any TAI-UTC table (tzdata leap-seconds.list).
 */
namespace vanetza_idf::its_time {

/// Unix time (seconds since 1970-01-01T00:00:00Z, no leap seconds) of the ITS epoch.
constexpr std::int64_t epoch_unix_seconds = 1072915200;

/// Unix instants at which UTC gained a leap second after the ITS epoch: 2006-01-01,
/// 2009-01-01, 2012-07-01, 2015-07-01, 2017-01-01 (each 00:00:00Z, the first second
/// after the inserted 23:59:60). TAI-UTC was 32 s at the epoch and is 37 s since 2017.
constexpr std::array<std::int64_t, 5> leap_second_unix_seconds = {
    1136073600, 1230768000, 1341100800, 1435708800, 1483228800};

/// Number of leap seconds inserted between the ITS epoch and the given Unix instant.
constexpr int leap_seconds_since_epoch(std::int64_t unix_seconds) {
    int count = 0;
    for (auto at : leap_second_unix_seconds) if (unix_seconds >= at) ++count;
    return count;
}

/// TAI microseconds since the ITS epoch for a Unix instant given as seconds and an
/// additional sub-second part in microseconds.
constexpr std::int64_t microseconds_since_epoch(std::int64_t unix_seconds, std::int64_t sub_second_microseconds = 0) {
    return (unix_seconds - epoch_unix_seconds + leap_seconds_since_epoch(unix_seconds)) * 1000000 + sub_second_microseconds;
}

/// The same for a std::chrono system clock instant (Unix time on every platform this library targets).
inline std::chrono::microseconds since_epoch(std::chrono::system_clock::time_point at) {
    // ("unix" itself is a predefined macro on GNU/Linux)
    const auto unix_us = std::chrono::duration_cast<std::chrono::microseconds>(at.time_since_epoch()).count();
    const std::int64_t seconds = unix_us >= 0 ? unix_us / 1000000 : -((-unix_us + 999999) / 1000000);
    return std::chrono::microseconds(microseconds_since_epoch(seconds, unix_us - seconds * 1000000));
}

/// TS 102 894-2 TimestampIts (milliseconds) for a system clock instant.
inline std::uint64_t timestamp_its(std::chrono::system_clock::time_point at) {
    return static_cast<std::uint64_t>(since_epoch(at).count() / 1000);
}

/// IEEE Std 1609.2 Time32 (seconds) for a system clock instant.
inline std::uint32_t time32(std::chrono::system_clock::time_point at) {
    return static_cast<std::uint32_t>(since_epoch(at).count() / 1000000);
}

/// Inverse: Unix microseconds for TAI microseconds since the ITS epoch. An instant inside an
/// inserted leap second (UTC 23:59:60) has no Unix second of its own and maps onto the
/// following 00:00:00.
constexpr std::int64_t unix_microseconds(std::int64_t microseconds_since_its_epoch) {
    const std::int64_t tai_seconds = microseconds_since_its_epoch / 1000000;
    int inserted = 0;
    for (std::size_t i = 0; i < leap_second_unix_seconds.size(); ++i) {
        // TAI value (since the ITS epoch) of the first second after the i-th insertion
        const std::int64_t tai_of_leap = leap_second_unix_seconds[i] - epoch_unix_seconds + static_cast<std::int64_t>(i + 1);
        if (tai_seconds >= tai_of_leap) ++inserted;
    }
    return (tai_seconds + epoch_unix_seconds - inserted) * 1000000 + microseconds_since_its_epoch % 1000000;
}

} // namespace vanetza_idf::its_time
