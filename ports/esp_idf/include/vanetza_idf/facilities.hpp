#pragma once
#include <vanetza_idf/access.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/support/uper_decoder.h>
#if VIDF_CAM
#include <vanetza/asn1/its/r2/CAM.h>
#endif
#if VIDF_DENM
#include <vanetza/asn1/its/r2/DENM.h>
#endif
#if VIDF_VAM
#include <vanetza/asn1/its/r2/VAM.h>
#endif

namespace vanetza_idf::facilities {
template<class T>
struct CompletePerMessage : vanetza::asn1::asn1c_per_wrapper<T> {
    using vanetza::asn1::asn1c_per_wrapper<T>::asn1c_per_wrapper;

    bool decode_exact(const vanetza::ByteBuffer& bytes) {
        if (bytes.empty()) return false;
        // X.691 complete encoding: consume the PDU and only its zero padding.
        // Comparing a re-encoding would incorrectly reject unknown extensions
        // which an extensible ASN.1 decoder is permitted to skip.
        void* decoded = nullptr;
        asn_codec_ctx_t context{};
        context.max_stack_size = 16384;
        const auto result = uper_decode(&context, &this->m_type, &decoded,
                                        bytes.data(), bytes.size(), 0, 0);
        const bool complete = result.code == RC_OK && result.consumed > 0 &&
            (result.consumed + 7) / 8 == bytes.size();
        const unsigned padding = complete ? (8 - result.consumed % 8) % 8 : 0;
        if (!complete || (bytes.back() & ((1u << padding) - 1u))) {
            vanetza::asn1::free(this->m_type, decoded);
            return false;
        }
        vanetza::asn1::free(this->m_type, this->m_struct);
        this->m_struct = static_cast<T*>(decoded);
        return true;
    }
};
// Explicit R2 aliases avoid Vanetza's backwards-compatible R1 Cam/Denm aliases.
// IF-FAC-001: TS 103 900 V2.3.1, TS 103 831 V2.3.1,
// TS 103 300-3 V2.3.1 ASN.1; CDD TS 102 894-2 V2.4.1.
#if VIDF_CAM
struct Cam : CompletePerMessage<Vanetza_ITS2_CAM_t> {
    Cam() : CompletePerMessage(asn_DEF_Vanetza_ITS2_CAM) {}
};
#endif
#if VIDF_DENM
struct Denm : CompletePerMessage<Vanetza_ITS2_DENM_t> {
    Denm() : CompletePerMessage(asn_DEF_Vanetza_ITS2_DENM) {}
};
#endif
#if VIDF_VAM
struct Vam : CompletePerMessage<Vanetza_ITS2_VAM_t> {
    Vam() : CompletePerMessage(asn_DEF_Vanetza_ITS2_VAM) {}
};
#endif

enum class Kind { cam, denm, vam };
struct Descriptor { std::uint16_t port; unsigned message_id; unsigned protocol_version; };
Descriptor descriptor(Kind);

/** Decode + constraints + identity + exact UPER consumption.
 * This boundary validates an encoded PDU. It is NOT a complete CA, DEN or VRU
 * Basic Service: generation rules/lifecycle/SSP decisions belong to that service.
 */
Result validate_pdu(Kind, const vanetza::ByteBuffer&, std::size_t maximum = 1394);

/** Application owns generation and lifecycle; this function selects the standard
 * BTP port and validates the Release 2 PDU before entering the NF-SAP.
 */
#if VIDF_NETWORK
}
#include <vanetza_idf/stack.hpp>
namespace vanetza_idf::facilities {
Result send(Stack&, Kind, vanetza::ByteBuffer, BtpRequest transport);
#endif
}
