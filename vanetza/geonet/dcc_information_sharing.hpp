#ifndef DCC_INFORMATION_SHARING_HPP_GZCSHZLD
#define DCC_INFORMATION_SHARING_HPP_GZCSHZLD

#include <vanetza/common/clock.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/common/unit_interval.hpp>
#include <vanetza/geonet/cbr_aggregator.hpp>
#include <vanetza/geonet/dcc_field_generator.hpp>

namespace vanetza
{

class Runtime;

namespace geonet
{

class LocationTable;

/**
 * DccInformationSharing realises the DCC_NET behaviour for ITS-G5, originally specified by
 * TS 102 636-4-2 V1.1.1 and carried forward by TS 103 836-4-2 V2.1.1 clauses 5.3-5.4
 * (Release 2; the CBR_G algorithm and trigger cadence implemented here match the current
 * text step-for-step). CBR_target corresponds to the Release-2 protocol constant
 * itsGNCBRTarget (TS 103 836-4-2 V2.1.1 Annex A: 0,62), which supersedes the value this
 * class's original author had to guess at from TS 102 687's undefined NDL_maxChannelUse.
 */
class DccInformationSharing : public DccFieldGenerator
{
public:
    /**
     * Create DCC_net instance
     *
     * \param rt Runtime for scheduling periodic update cycles
     * \param lt Location Table with LocTEX_G5 entries
     * \param target CBR_target value (usually NDL_maxChannelLoad)
     * \param delay Delaying first update cycle randomly
     *
     * \note Set random delay interval when multiple stations are created at the same time!
     *       Values shall be distributed uniformly across full integer range.
     */
    DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target, UnitInterval delay);
    DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target);

    DccField generate_dcc_field() override;

    /**
     * Update local CBR measurement
     *
     * Local measurement rate is decoupled from processing in DCC_net,
     * i.e. DccInformationSharing buffers the given value and the latest
     * measurement value when its internal update cycle runs.
     *
     * \param cbr local CBR measurement
     */
    void update_local_cbr(dcc::ChannelLoad cbr);

    /**
     * Set packet TX power
     *
     * \param power Packet transmission output power in dBm
     */
    void set_tx_power(unsigned power);

private:
    void trigger();

    Runtime& m_runtime;
    const LocationTable& m_location_table;
    const dcc::ChannelLoad m_cbr_target;
    dcc::ChannelLoad m_cbr_local;
    unsigned m_tx_power;
    CbrAggregator m_aggregator;
    Clock::duration m_trigger_interval;
    Timestamp m_last_aggregation;
    Hook<const CbrAggregator&> m_update_hook;

public:
    /**
     * on_global_cbr_update is called at each update cycle,
     * i.e. when a new global CBR has been calculated
     */
    HookRegistry<const CbrAggregator&> on_global_cbr_update;
};

} // namespace geonet
} // namespace vanetza

#endif /* DCC_INFORMATION_SHARING_HPP_GZCSHZLD */

