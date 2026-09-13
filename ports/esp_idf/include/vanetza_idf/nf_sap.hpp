#pragma once
#include <vanetza_idf/stack.hpp>
#include <utility>

namespace vanetza_idf::NF_SAP {

enum class SecurityProfile { UNSECURED, SECURED };

/** BTP-DATA.request language binding.
 * TS 102 723-11 V2.0.0 clause 5 incorporates V1.1.1; the complete BTP
 * parameter contract is TS 103 836-5-1 V2.1.1 Annex A.2.
 * '-' and '.' in primitive names become '_' in C++ identifiers.
 * Parameters retain the extracted snake_case names. length counts octets;
 * gn_maximum_packet_lifetime uses the GN lifetime value, not an unlabelled int.
 */
struct BTP_DATA_request {
    vanetza::ByteBuffer fl_sdu;
    std::size_t length = 0;
    BtpType btp_type = BtpType::b;
    std::uint16_t destination_port = 0;
    std::optional<std::uint16_t> destination_port_info;
    std::optional<std::uint16_t> source_port;
    vanetza::geonet::TransportType gn_packet_transport_type = vanetza::geonet::TransportType::SHB;
    vanetza::geonet::CommunicationProfile gn_communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    std::optional<SecurityProfile> gn_security_profile;
    vanetza::geonet::TrafficClass gn_traffic_class;
    std::optional<vanetza::geonet::Lifetime> gn_maximum_packet_lifetime;
    vanetza::geonet::DestinationVariant gn_destination_address = nullptr;
    std::optional<unsigned> gn_maximum_hop_limit;
    std::optional<vanetza::geonet::DataRequest::Repetition> gn_repetition;
    vanetza::ItsAid its_aid = 0;
    vanetza::ByteBuffer permissions;
    // SN-ENCAP context_information (TS 102 723-8 V1.1.1 Table 24), forwarded by GN
    // as the TRANSP_CORE.request Security context information (TS 103 836-4-1 Annex J.2)
    vanetza::ByteBuffer context_information;
};

/** BTP-DATA.indication, TS 103 836-5-1 V2.1.1 Annex A.3.
 * received_fl_sdu is the facilities payload; gn preserves the complete
 * router indication, including source position and security report metadata.
 */
struct BTP_DATA_indication {
    vanetza::ByteBuffer received_fl_sdu;
    std::size_t length;
    BtpType btp_type;
    std::uint16_t destination_port;
    std::optional<std::uint16_t> destination_port_info;
    std::optional<std::uint16_t> source_port;
    vanetza::geonet::DataIndication gn;
    std::optional<vanetza::ByteBuffer> certificate_id;
};

inline BTP_DATA_indication BTP_DATA_indication_from(BtpIndication indication) {
    const auto length = indication.data.size();
    return {std::move(indication.data), length, indication.type,
            indication.destination_port, indication.destination_port_info,
            indication.source_port, std::move(indication.gn),
            std::move(indication.certificate_id)};
}

inline Result BTP_DATA_request_submit(Stack& stack, BTP_DATA_request primitive) {
    if (primitive.length != primitive.fl_sdu.size()) return Result::invalid_argument;
    if (primitive.gn_security_profile) {
        if (*primitive.gn_security_profile != SecurityProfile::SECURED &&
            *primitive.gn_security_profile != SecurityProfile::UNSECURED)
            return Result::invalid_argument;
        const bool secured = *primitive.gn_security_profile == SecurityProfile::SECURED;
        // A per-request profile cannot silently change station security policy.
        if (secured != stack.config().mib.itsGnSecurity) return Result::unsupported;
    }
    BtpRequest request;
    request.type = primitive.btp_type;
    request.source_port = primitive.source_port;
    request.destination_port = primitive.destination_port;
    request.destination_port_info = primitive.destination_port_info;
    request.transport = primitive.gn_packet_transport_type;
    request.communication_profile = primitive.gn_communication_profile;
    request.traffic_class = primitive.gn_traffic_class;
    request.maximum_lifetime = primitive.gn_maximum_packet_lifetime;
    request.destination = primitive.gn_destination_address;
    request.maximum_hop_limit = primitive.gn_maximum_hop_limit;
    request.repetition = primitive.gn_repetition;
    request.its_aid = primitive.its_aid;
    request.permissions = std::move(primitive.permissions);
    request.security_context = std::move(primitive.context_information);
    request.data = std::move(primitive.fl_sdu);
    return stack.request(std::move(request));
}
}
