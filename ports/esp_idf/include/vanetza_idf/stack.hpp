#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/security/security_entity.hpp>
#include <functional>
#include <memory>

namespace vanetza_idf {
enum class BtpType { a, b };

/** NF-SAP / BTP-DATA.request: TS 103 836-5-1 V2.1.1 Annex A.2
 * and clauses 7, 8.2 (IF-NF-001); TS 102 723-11 V2.0.0 clause 5
 * incorporates V1.1.1, including its clause 5.1 GeoAware SAP.
 * All port numbers are HOST order. data.size() is the Length parameter.
 * Omitted GN parameters inherit the configured MIB. No magic sentinel values.
 */
struct BtpRequest {
    BtpType type = BtpType::b;
    std::optional<std::uint16_t> source_port;
    std::uint16_t destination_port = 0;
    std::optional<std::uint16_t> destination_port_info;
    vanetza::geonet::TransportType transport = vanetza::geonet::TransportType::SHB;
    vanetza::geonet::DestinationVariant destination = nullptr;
    vanetza::geonet::CommunicationProfile communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    // The selected security entity implements this profile; ITS-AID, SSP and
    // context information are SN-ENCAP inputs (TS 102 723-8 V2.0.0 clause 5 /
    // V1.1.1 Table 24) that GN forwards unchanged (TS 103 836-4-1 V2.2.1
    // Table 34, Annex J.2 "Security context information").
    std::optional<std::uint32_t> security_profile;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
    vanetza::ByteBuffer security_context; // see security::context for the values this library defines
    std::optional<vanetza::geonet::Lifetime> maximum_lifetime;
    std::optional<vanetza::geonet::DataRequest::Repetition> repetition;
    std::optional<unsigned> maximum_hop_limit;
    vanetza::geonet::TrafficClass traffic_class;
    vanetza::ByteBuffer data;
};

/** BTP-DATA.indication: TS 103 836-5-1 V2.1.1 Annex A.3/8.3 (IF-NF-002).
 * gn retains the transport, destination, source vector, report, permissions,
 * traffic class, remaining lifetime and hop limit. Owns the received payload.
 */
struct BtpIndication {
    BtpType type;
    std::optional<std::uint16_t> source_port;
    std::uint16_t destination_port;
    std::optional<std::uint16_t> destination_port_info;
    vanetza::geonet::DataIndication gn;
    std::optional<vanetza::ByteBuffer> certificate_id;
    vanetza::ByteBuffer data;
};

/** GN-DATA.request: TS 103 836-4-1 V2.2.1 clause 9.3 N-SAP (EN 302 636-4-1
 * clause 9.3 heritage), IF-GN-001. Unlike BtpRequest, data is the raw SDU
 * with no assumed upper-layer header; the Common Header next_header is
 * "Any". Only SHB and GBC are implemented; GUC, GAC and TSB are rejected
 * as Result::unsupported (GAP-GN-001), matching Stack::request(BtpRequest).
 */
struct GnRequest {
    vanetza::geonet::TransportType transport = vanetza::geonet::TransportType::SHB;
    vanetza::geonet::DestinationVariant destination = nullptr; // Area for GBC, null for SHB
    vanetza::geonet::CommunicationProfile communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    vanetza::geonet::TrafficClass traffic_class;
    std::optional<vanetza::geonet::Lifetime> maximum_lifetime;
    std::optional<unsigned> maximum_hop_limit;
    std::optional<vanetza::geonet::DataRequest::Repetition> repetition;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
    vanetza::ByteBuffer security_context; // TS 103 836-4-1 V2.2.1 Annex J.2 Security context information
    vanetza::ByteBuffer data;
};

/** GN-DATA.indication for a packet whose Common Header next_header is "Any"
 * (no upper protocol registered by BtpRequest's handler), TS 103 836-4-1
 * V2.2.1 clause 9.3. gn retains the complete router indication.
 */
struct GnIndication {
    vanetza::geonet::DataIndication gn;
    vanetza::ByteBuffer data;
};

struct StackConfig {
    vanetza::geonet::MIB mib;
    std::size_t maximum_gnpdu = 4096;
    std::uint32_t security_profile = 0;
    AlDataRequest radio_parameters;
    StackConfig();
};

/** Portable network/transport module for the NF-SAP entry point.
 * The caller serializes all calls in ONE task/event loop, including reception,
 * clock advancement and destruction. Access/SecurityEntity must outlive Stack.
 * Timer source is injectable for host tests, HIL and ESP-IDF esp_timer.
 * No FreeRTOS task, radio, BLE link, socket or filesystem is opened internally.
 * This is a port of the upstream router; see docs/idf/conformance.md for R2 gaps.
 */
class Stack {
public:
    using Receive = std::function<void(BtpIndication)>;
    using ReceiveGn = std::function<void(GnIndication)>;
    using Report = std::function<void(Result)>;
    Stack(StackConfig, vanetza::ManualRuntime&, Access&,
          vanetza::security::SecurityEntity* security = nullptr);
    ~Stack();
    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;
    Result request(BtpRequest);
    Result request(GnRequest);
    Result indicate(AlDataIndication);
    Result update_position(const vanetza::PositionFix&);
    Result advance(vanetza::Clock::time_point);
    void on_receive(Receive);
    void on_receive_gn(ReceiveGn);
    void on_access_result(Report);
    const StackConfig& config() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
