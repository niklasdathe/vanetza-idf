#ifndef DCC_MCO_FIELD_HPP_RLZ4PQMF
#define DCC_MCO_FIELD_HPP_RLZ4PQMF

#include <vanetza/common/bit_number.hpp>
#include <vanetza/dcc/channel_load.hpp>
#include <cstdint>

namespace vanetza
{
namespace geonet
{

/**
 * DCC-MCO (Multi Channel Operations) was introduced by TS 102 636-4-2 V1.1.1 and is carried
 * forward unchanged by TS 103 836-4-2 V2.1.1 clause 6.3.3 Table 3 (Release 2): Octet 40
 * CBR_L_0_Hop = floor(CBR_L_0_Hop x 255), Octet 41 CBR_L_1_Hop likewise, Octet 42 bits 0-4 TX
 * power [0;31] dBm, Octet 43 reserved. This field layout was cross-checked bit-for-bit against
 * the current V2.1.1 text; only this docstring's citation was stale.
 * DccMcoField implements the SHB header field extension.
 */
class DccMcoField
{
public:
    using ChannelLoad = dcc::ChannelLoad;

    DccMcoField();

    // copy operations
    DccMcoField(const DccMcoField&) = default;
    DccMcoField& operator=(const DccMcoField&) = default;

    // conversion from/to 4 bytes (host byte order)
    explicit DccMcoField(uint32_t);
    DccMcoField& operator=(uint32_t);
    explicit operator uint32_t() const;

    void local_cbr(const ChannelLoad&);
    ChannelLoad local_cbr() const;

    void neighbour_cbr(const ChannelLoad&);
    ChannelLoad neighbour_cbr() const;

    /**
     * Output power of packet transmission
     * \return [0; 31] dBm (values are cramped at limits)
     */
    void output_power(unsigned dbm);
    unsigned output_power() const;

private:
    using cbr_type = uint8_t;
    using power_type = BitNumber<unsigned, 5>;

    cbr_type m_cbr_l0_hop; /*< local CBR measurement */
    cbr_type m_cbr_l1_hop; /*< maximum CBR measurement from 1-hop neighbours */
    power_type m_output_power; /*< output power of packet transmission */
};

} // namespace geonet
} // namespace vanetza

#endif /* DCC_MCO_FIELD_HPP_RLZ4PQMF */

