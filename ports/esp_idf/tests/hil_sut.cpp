#include "hil_sut.hpp"
#include <vanetza_idf/nf_sap.hpp>
#if VIDF_SECURITY
#include <vanetza_idf/security.hpp>
#include <vanetza_idf/credentials.hpp>
#include "test_backend.hpp"
#include <filesystem>
#include <fstream>
#include <iterator>
#endif
#if VIDF_CAM || VIDF_DENM
#include <vanetza_idf/facilities.hpp>
#endif
#include <algorithm>
#include <cmath>
#include <chrono>

namespace vidf_test {
using namespace vanetza_idf;
using vanetza::ByteBuffer;
namespace {
void u16(ByteBuffer& out, std::size_t n) { out.push_back(n >> 8); out.push_back(n); }
std::uint16_t read16(const ByteBuffer& in, std::size_t n) { return (in[n] << 8) | in[n + 1]; }

vanetza::PositionFix fixed_position(double latitude, double longitude, vanetza::Clock::time_point now) {
    vanetza::PositionFix fix {};
    fix.timestamp = now;
    fix.latitude = latitude * vanetza::units::degree;
    fix.longitude = longitude * vanetza::units::degree;
    fix.speed = 0.0 * vanetza::units::si::meters_per_second;
    fix.course = 0.0 * vanetza::units::true_north_degrees;
    return fix;
}
}

#if VIDF_SECURITY
// Security profile of the SUT: an application-provisioned trust configuration and ticket
// pool, exactly what a station would load from its own PKI output files.
class Sut::Security : public vanetza::PositionProvider {
public:
    TestBackend backend;
    security::TrustConfiguration trust;
    security::CertificatePool pool {backend};
    std::unique_ptr<security::SecurityEntity> entity;
    vanetza::PositionFix fix;
    const vanetza::PositionFix& position_fix() override { return fix; }

    static ByteBuffer read(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        return ByteBuffer(std::istreambuf_iterator<char>(in), {});
    }

    // run-time provisioning: everything the bundle carries, through the same checks
    Result load(const ByteBuffer& bundle) {
        security::Credentials credentials;
        if (!security::decode(bundle, credentials) || credentials.roots.empty() || credentials.tickets.empty())
            return Result::invalid_argument;
        return security::apply(credentials, trust, pool).result;
    }

    // ETSI IUT install: what an IUT under the official Security ATS holds. Roots and authorities
    // are offered to the trust configuration as they are (one it refuses, e.g. an AA of an
    // unknown root, stays unknown: that is what the "unknown AA" cases rely on); every AT is
    // added with the curve its key fits (the pool checks the key against the certificate).
    // The default ticket is `profile.ticket`.
    Result load_etsi(const SecurityProfile& profile, vanetza::security::HashedId8& fallback) {
        namespace fs = std::filesystem;
        std::vector<fs::path> files;
        for (const auto& entry : fs::directory_iterator(profile.etsi_install)) files.push_back(entry.path());
        std::sort(files.begin(), files.end());
        const auto ends = [](const fs::path& p, const std::string& tail) {
            const auto name = p.filename().string();
            return name.size() >= tail.size() && name.compare(name.size() - tail.size(), tail.size(), tail) == 0;
        };
        const auto unknown = [&](const fs::path& p) {
            return std::find(profile.etsi_unknown.begin(), profile.etsi_unknown.end(), p.stem().string()) != profile.etsi_unknown.end();
        };
        std::size_t roots = 0;
        for (const auto& p : files)
            if (ends(p, "_RCA.oer") && trust.add_root(read(p.string())) == Result::accepted) ++roots;
        if (!roots) return Result::invalid_argument;
        for (bool progress = true; progress;) { // an AA may be issued by another AA
            progress = false;
            for (const auto& p : files)
                if (ends(p, "_AA.oer") && !unknown(p) && trust.add_authority(read(p.string())) == Result::accepted) progress = true;
        }
        bool found_default = false;
        for (const auto& p : files) {
            if (p.extension() != ".vkey") continue;
            auto certificate = p; certificate.replace_extension(".oer");
            const auto coer = read(certificate.string());
            const auto octets = read(p.string());
            if (coer.empty()) continue;
            using vanetza::security::KeyType;
            const std::vector<KeyType> curves = octets.size() == 48
                ? std::vector<KeyType> {KeyType::BrainpoolP384r1}
                : std::vector<KeyType> {KeyType::NistP256, KeyType::BrainpoolP256r1};
            for (auto type : curves) {
                vanetza::security::PrivateKey key;
                key.type = type;
                key.key = octets;
                if (pool.add(coer, key) != Result::accepted) continue;
                if (p.stem().string() == profile.ticket) { fallback = pool.tickets().back().digest; found_default = true; }
                break;
            }
        }
        return found_default ? Result::accepted : Result::invalid_argument;
    }

    Result load(const SecurityProfile& profile) {
        const auto file = [&](const std::string& name, const char* ext) { return read(profile.pool + "/" + name + ext); };
        if (trust.add_root(file(profile.root, ".oer")) != Result::accepted) return Result::invalid_argument;
        for (const auto& authority : profile.authorities)
            if (trust.add_authority(file(authority, ".oer")) != Result::accepted) return Result::invalid_argument;
        const auto key_octets = file(profile.ticket, ".vkey");
        vanetza::security::PrivateKey key;
        key.type = key_octets.size() == 48 ? vanetza::security::KeyType::BrainpoolP384r1 : vanetza::security::KeyType::NistP256;
        key.key = key_octets;
        return pool.add(file(profile.ticket, ".oer"), key);
    }
};
#else
class Sut::Security {};
#endif

Sut::Sut() = default;
Sut::~Sut() = default;
void Sut::configure(SecurityProfile profile) { profile_ = std::move(profile); }
Result Sut::provision(const ByteBuffer& bundle) {
#if VIDF_SECURITY
    security::Credentials probe;
    if (!security::decode(bundle, probe)) return Result::invalid_argument; // structure only; reset() applies it
    bundle_ = bundle;
    return Result::accepted;
#else
    (void)bundle;
    return Result::unsupported;
#endif
}

void Sut::record(std::uint8_t kind, ByteBuffer bytes) {
    if (record_bytes_ + bytes.size() + 3 > 3800 || records_.size() >= 32) { overflow_ = true; return; }
    ByteBuffer frame {kind}; u16(frame, bytes.size());
    frame.insert(frame.end(), bytes.begin(), bytes.end());
    record_bytes_ += frame.size(); records_.push_back(std::move(frame));
}
Result Sut::request(AlDataRequest request) {
    if (link_layer_) {
        ByteBuffer frame(request.destination.octets.begin(), request.destination.octets.end());
        frame.insert(frame.end(), request.source.octets.begin(), request.source.octets.end());
        frame.insert(frame.end(), request.data.begin(), request.data.end());
        record(4, std::move(frame));
    } else {
        record(1, std::move(request.data));
    }
    return overflow_ ? Result::resource_limit : Result::accepted;
}
Result Sut::reset() {
    stack_.reset(); // Router timer cancellation precedes runtime destruction.
    security_.reset();
    runtime_ = std::make_unique<vanetza::ManualRuntime>();
    StackConfig config;
    config.mib.itsGnLocalGnAddr.mid({2, 0, 0, 0, 0, 1});
    vanetza::security::SecurityEntity* entity = nullptr;
    if (profile_.pool.empty() && profile_.etsi_install.empty() && bundle_.empty()) {
        config.mib.itsGnSecurity = false; // explicit unsecured BTP/GN test PICS
        config.mib.vanetzaDisableBeaconing = !beaconing_;
        if (auto_address_) config.mib.itsGnLocalAddrConfMethod = vanetza::geonet::AddrConfMethod::Auto;
    } else {
#if VIDF_SECURITY
        security_ = std::make_unique<Security>();
        Result loaded;
        if (!bundle_.empty()) loaded = security_->load(bundle_);
        else if (!profile_.etsi_install.empty()) {
            // UtGnInitialize.hashedId8 selects the AT (TS.ITS f_setupIutCertificate); zero = default
            vanetza::security::HashedId8 digest {};
            loaded = security_->load_etsi(profile_, digest);
            if (loaded == Result::accepted && selected_.size() == digest.size() &&
                std::any_of(selected_.begin(), selected_.end(), [](std::uint8_t b) { return b != 0; }))
                std::copy(selected_.begin(), selected_.end(), digest.begin());
            if (loaded == Result::accepted) loaded = security_->pool.select(digest);
        } else loaded = security_->load(profile_);
        if (loaded != Result::accepted) { security_.reset(); return loaded; }
        security_->entity = std::make_unique<security::SecurityEntity>(*runtime_, *security_, security_->backend,
                                                                       security_->pool, security_->trust);
        entity = security_->entity.get();
        config.mib.itsGnSecurity = true;
        config.mib.vanetzaDisableBeaconing = false; // the Security ATS observes secured beacons (GN-MGMT)
        if (profile_.anonymous_address) config.mib.itsGnLocalAddrConfMethod = vanetza::geonet::AddrConfMethod::Anonymous;
#else
        return Result::unsupported;
#endif
    }
    carrier_interval_[0] = carrier_interval_[1] = 0;
    carrier_pending_[0] = carrier_pending_[1] = false;
    stack_ = std::make_unique<Stack>(config, *runtime_, *this, entity);
    stack_->on_receive([this](BtpIndication received) {
        auto indication = NF_SAP::BTP_DATA_indication_from(std::move(received));
        ByteBuffer data {static_cast<std::uint8_t>(indication.btp_type == BtpType::b)};
        u16(data, indication.destination_port);
        u16(data, indication.source_port.value_or(indication.destination_port_info.value_or(0)));
        data.insert(data.end(), indication.received_fl_sdu.begin(), indication.received_fl_sdu.end());
        record(2, std::move(data));
    });
    stack_->on_receive_gn([this](GnIndication received) {
        // GN-DATA.indication with no registered upper protocol (raw test SDU).
        record(3, std::move(received.data));
    });
    return position(52.0, 13.0);
}

// The position vector carries the clock's time; it is refreshed on every tick so the
// router never keeps an unset (epoch) timestamp, which suppresses beacons upstream.
Result Sut::position(double latitude, double longitude) {
    fix_ = fixed_position(latitude, longitude, runtime_->now());
#if VIDF_SECURITY
    if (security_) security_->fix = fix_;
#endif
    return stack_->update_position(fix_);
}

Result Sut::carrier(std::uint8_t kind, std::uint16_t sequence) {
    // Syntactically valid Release 2 PDUs so the security profile of the carrier (CAM: TS 103 097
    // clause 7.1.1, DENM: clause 7.1.2) can be observed; no CA/DEN service semantics.
#if VIDF_CAM
    if (kind == 0) {
        facilities::Cam cam;
        cam->header.protocolVersion = 2; cam->header.messageId = 2; cam->header.stationId = 42;
        auto& cp = cam->cam.camParameters;
        cp.basicContainer.stationType = 5;
        cp.highFrequencyContainer.present = Vanetza_ITS2_HighFrequencyContainer_PR_rsuContainerHighFrequency;
        auto& pos = cp.basicContainer.referencePosition;
        pos.latitude = here_latitude(); pos.longitude = here_longitude(); // the station's current fix
        pos.positionConfidenceEllipse.semiMajorAxisLength = 4095;
        pos.positionConfidenceEllipse.semiMinorAxisLength = 4095;
        pos.positionConfidenceEllipse.semiMajorAxisOrientation = 3601;
        pos.altitude.altitudeValue = 800001; pos.altitude.altitudeConfidence = 15;
        return facilities::send(*stack_, facilities::Kind::cam, cam.encode(), BtpRequest {});
    }
#endif
#if VIDF_DENM
    if (kind == 1) {
        facilities::Denm denm;
        denm->header.protocolVersion = 2; denm->header.messageId = 1; denm->header.stationId = 42;
        auto& dm = denm->denm.management;
        dm.actionId.originatingStationId = 42;
        dm.actionId.sequenceNumber = sequence;
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(runtime_->now().time_since_epoch()).count();
        if (asn_long2INTEGER(&dm.detectionTime, now_ms) != 0 || asn_long2INTEGER(&dm.referenceTime, now_ms) != 0)
            return Result::rejected;
        dm.eventPosition.latitude = here_latitude(); dm.eventPosition.longitude = here_longitude();
        dm.eventPosition.positionConfidenceEllipse.semiMajorConfidence = 4095;
        dm.eventPosition.positionConfidenceEllipse.semiMinorConfidence = 4095;
        dm.eventPosition.positionConfidenceEllipse.semiMajorOrientation = 3601;
        dm.eventPosition.altitude.altitudeValue = 800001; dm.eventPosition.altitude.altitudeConfidence = 15;
        // DENM dissemination is GeoBroadcast into the relevance area around the event
        // position (TS 103 831 V2.2.1 clause 5.4.2 / EN 302 637-3 clause 5.4.2), so the
        // carrier uses GBC with a circular destination area; only the transport is exercised.
        BtpRequest request;
        request.transport = vanetza::geonet::TransportType::GBC;
        vanetza::geonet::Area area;
        vanetza::geonet::Circle circle;
        circle.r = 500.0 * vanetza::units::si::meter;
        area.shape = circle;
        area.position = vanetza::geonet::GeodeticPosition(fix_.latitude, fix_.longitude); // event at the station
        area.angle = vanetza::units::Angle(0.0 * vanetza::units::degree);
        request.destination = area;
        return facilities::send(*stack_, facilities::Kind::denm, denm.encode(), std::move(request));
    }
#endif
    return Result::unsupported;
}

long Sut::here_latitude() const { return std::lround(fix_.latitude / vanetza::units::degree * 1e7); }
long Sut::here_longitude() const { return std::lround(fix_.longitude / vanetza::units::degree * 1e7); }

ByteBuffer Sut::execute(const ByteBuffer& input) {
    records_.clear(); record_bytes_ = 0; overflow_ = false;
    Result result = Result::invalid_argument;
    try {
        if ((input.size() == 1 || input.size() == 9) && input[0] == 0) {
            selected_.assign(input.begin() + 1, input.end());
            result = reset();
        }
        else if (input.size() > 1 && input[0] == 9) {
            // credentials for the next reset: [9][credentials.hpp bundle]; allowed before any reset
            result = provision(ByteBuffer(input.begin() + 1, input.end()));
        }
        else if (!stack_) result = Result::rejected;
        else if (input.size() >= 6 && input[0] == 1 && input[1] <= 1) {
            NF_SAP::BTP_DATA_request request;
            request.btp_type = input[1] ? BtpType::b : BtpType::a;
            request.destination_port = read16(input, 2);
            if (request.btp_type == BtpType::a) request.source_port = read16(input, 4);
            else request.destination_port_info = read16(input, 4);
            request.fl_sdu.assign(input.begin() + 6, input.end());
            request.length = request.fl_sdu.size();
            result = NF_SAP::BTP_DATA_request_submit(*stack_, std::move(request));
        } else if (input.size() > 13 && input[0] == 2) {
            AlDataIndication indication;
            std::copy(input.begin() + 1, input.begin() + 7, indication.source.octets.begin());
            std::copy(input.begin() + 7, input.begin() + 13, indication.destination.octets.begin());
            indication.data.assign(input.begin() + 13, input.end());
            result = stack_->indicate(std::move(indication));
        } else if (input.size() >= 2 && input[0] == 3) {
            // GN-DATA.request, SHB only (GAP-GN-001): [3][raw traffic class][payload].
            GnRequest request;
            request.traffic_class = vanetza::geonet::TrafficClass(input[1]);
            request.data.assign(input.begin() + 2, input.end());
            result = stack_->request(std::move(request));
        } else if (input.size() >= 19 && input[0] == 10) {
            // GN-DATA.request GBC: [10][tc][shape][lat][lon][a u16][b u16][angle u16][lifetime ms u16][payload]
            const auto i32 = [&](std::size_t at) {
                return static_cast<std::int32_t>((std::uint32_t(input[at]) << 24) | (std::uint32_t(input[at + 1]) << 16) |
                                                  (std::uint32_t(input[at + 2]) << 8) | input[at + 3]);
            };
            using vanetza::units::si::meters;
            vanetza::geonet::Area area;
            const double a = read16(input, 11), b = read16(input, 13);
            if (input[2] == 0) { vanetza::geonet::Circle c; c.r = a * meters; area.shape = c; }
            else if (input[2] == 1) { vanetza::geonet::Rectangle r; r.a = a * meters; r.b = b * meters; area.shape = r; }
            else { vanetza::geonet::Ellipse e; e.a = a * meters; e.b = b * meters; area.shape = e; }
            area.position = vanetza::geonet::GeodeticPosition(i32(3) / 1.0e7 * vanetza::units::degree,
                                                               i32(7) / 1.0e7 * vanetza::units::degree);
            area.angle = vanetza::units::Angle(read16(input, 15) * vanetza::units::degree);
            GnRequest request;
            request.transport = vanetza::geonet::TransportType::GBC;
            request.destination = area;
            request.traffic_class = vanetza::geonet::TrafficClass(input[1]);
            if (const unsigned ms = read16(input, 17)) {
                // smallest Lifetime base whose 6-bit multiplier holds the value (TS 103 836-4-1 clause 9.6.4)
                using Base = vanetza::geonet::Lifetime::Base;
                vanetza::geonet::Lifetime lifetime;
                if (ms / 50 <= 63) lifetime.set(Base::Fifty_Milliseconds, ms / 50);
                else if (ms / 1000 <= 63) lifetime.set(Base::One_Second, ms / 1000);
                else if (ms / 10000 <= 63) lifetime.set(Base::Ten_Seconds, ms / 10000);
                else lifetime.set(Base::Hundred_Seconds, std::min(63u, ms / 100000));
                request.maximum_lifetime = lifetime;
            }
            request.data.assign(input.begin() + 19, input.end());
            result = stack_->request(std::move(request));
        } else if (input.size() == 9 && input[0] == 4) {
            // UtGnChangePosition-style fix: [4][lat i32 BE][lon i32 BE], 1e-7 degree units.
            const auto i32 = [&](std::size_t at) {
                return static_cast<std::int32_t>((std::uint32_t(input[at]) << 24) | (std::uint32_t(input[at + 1]) << 16) |
                                                  (std::uint32_t(input[at + 2]) << 8) | input[at + 3]);
            };
            result = position(i32(1) / 1.0e7, i32(5) / 1.0e7);
        } else if (input.size() == 9 && input[0] == 5) {
            std::uint64_t microseconds = 0;
            for (std::size_t i = 1; i < 9; ++i) microseconds = (microseconds << 8) | input[i];
            const vanetza::Clock::time_point time {std::chrono::microseconds(microseconds)};
            result = stack_->advance(time); // runs router timers: beacons come back as kind-1 records
            if (result == Result::accepted) result = position(fix_.latitude.value(), fix_.longitude.value());
            for (std::uint8_t kind = 0; kind < 2 && result == Result::accepted; ++kind) {
                if (carrier_pending_[kind]) {
                    carrier_pending_[kind] = false;
                    result = carrier(kind, carrier_pending_sequence_[kind]);
                } else if (carrier_interval_[kind] && time >= carrier_next_[kind]) {
                    // fixed grid, not relative to this tick: tick jitter must not stretch the period
                    const auto period = std::chrono::milliseconds(carrier_interval_[kind]);
                    carrier_next_[kind] += period;
                    if (carrier_next_[kind] <= time) carrier_next_[kind] = time + period; // clock jumped
                    result = carrier(kind, kind == 1 ? ++denm_sequence_ : 0);
                }
            }
        } else if ((input.size() == 2 || input.size() == 4) && (input[0] == 6 || input[0] == 8) && input[1] < 2) {
            const std::uint16_t sequence = input.size() == 4 ? read16(input, 2) : 0;
            if (input[0] == 6) result = carrier(input[1], sequence);
            else {
                carrier_pending_[input[1]] = true;
                carrier_pending_sequence_[input[1]] = sequence;
                result = Result::accepted;
            }
        } else if (input.size() == 4 && input[0] == 7 && input[1] < 2) {
            carrier_interval_[input[1]] = read16(input, 2);
            carrier_next_[input[1]] = runtime_->now();
            result = Result::accepted;
        } else if (input.size() == 1 && input[0] == 12) {
            // local GN_ADDR (TS 103 836-4-1 clause 6.3, 8 octets): the test system reports the IUT's
            // address in getLongPosVector from the IUT itself, not from assumed defaults
            const auto address = stack_->address();
            const unsigned first = (address.is_manually_configured() ? 0x8000u : 0u) |
                ((static_cast<unsigned>(address.station_type()) & 0x1fu) << 10) | (address.country_code().raw() & 0x3ffu);
            ByteBuffer octets {static_cast<std::uint8_t>(first >> 8), static_cast<std::uint8_t>(first)};
            octets.insert(octets.end(), address.mid().octets.begin(), address.mid().octets.end());
            record(5, std::move(octets));
            result = Result::accepted;
        } else if (input.size() == 9 && input[0] == 11) {
#if VIDF_SECURITY
            // pseudonym change to a named AT of the install (the SUT's own identifier change
            // policy is not what the Security ATS triggers here)
            vanetza::security::HashedId8 digest {};
            std::copy(input.begin() + 1, input.end(), digest.begin());
            result = security_ ? security_->pool.select(digest) : Result::rejected;
#else
            result = Result::unsupported;
#endif
        } else if (!input.empty() && input[0] > 12) result = Result::unsupported;
    } catch (const std::bad_alloc&) { result = Result::resource_limit; }
      catch (const std::exception&) { result = Result::rejected; }
    if (overflow_) result = Result::resource_limit;
    ByteBuffer output {static_cast<std::uint8_t>(result), static_cast<std::uint8_t>(records_.size())};
    for (const auto& record : records_) output.insert(output.end(), record.begin(), record.end());
    return output;
}
}
