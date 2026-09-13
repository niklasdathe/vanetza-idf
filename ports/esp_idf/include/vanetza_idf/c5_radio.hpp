#pragma once
#include <sdkconfig.h>
#if !defined(CONFIG_IDF_TARGET_ESP32C5) || !defined(CONFIG_VANETZA_IDF_RADIO_C5)
#error "C5Radio requires ESP32-C5 and CONFIG_VANETZA_IDF_RADIO_C5"
#endif
#include <vanetza_idf/access.hpp>
#include <esp_err.h>
#include <functional>
#include <memory>

namespace vanetza_idf {
struct C5RadioConfig {
    std::uint16_t channel_number = 180;
    double transmit_power_dbm = 10.0;
    unsigned receive_queue_length = 8;
    // Explicit laboratory mode until real CBR/DCC enforcement is integrated.
    // The default supports a receive-only second C5 without any packet TX.
    bool laboratory_transmission = false;
};

/** ITS-G5 AL_DATA device binding, EN 303 797 Annex B.2.
 * This adapter owns the Wi-Fi driver while started. Invoke start/stop/request/
 * poll in one application task. Radio callbacks only copy into a bounded queue.
 * No MQTT, Ethernet, storage, facilities service or test runtime is included.
 */
class C5Radio final : public Access {
public:
    using Receive = std::function<void(AlDataIndication)>;
    using Capture = std::function<void(const vanetza::ByteBuffer&, int, std::uint32_t)>;
    explicit C5Radio(C5RadioConfig = {});
    ~C5Radio();
    C5Radio(const C5Radio&) = delete;
    C5Radio& operator=(const C5Radio&) = delete;
    esp_err_t start();
    void stop();
    Result request(AlDataRequest) override;
    // Dispatch reception in the owning task. Capture contains the original
    // MPDU including FCS, before LLC/MAC removal; timestamp is radio-local us.
    void poll(const Receive&, const Capture& = {});
    std::uint32_t dropped_frames() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
