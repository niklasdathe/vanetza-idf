#include <vanetza_idf/c5_radio.hpp>
#include <vanetza_idf/its_g5_frame.hpp>
#include <esp_event.h>
#include <esp_wifi.h>
#include <hal/modem_syscon_ll.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <mutex>

extern "C" {
void phy_11p_set(int, int);
void phy_change_channel(int, int, int, int);
esp_err_t esp_wifi_80211_tx_custom(wifi_interface_t, const void*, int32_t, bool,
                                 wifi_tx_rate_config_t*, wifi_band_t, wifi_bandwidth_t);
}

namespace vanetza_idf {
class C5Radio::Impl {
public:
    struct Raw {
        std::uint16_t length;
        std::int8_t rssi;
        std::uint32_t timestamp;
        std::uint8_t bytes[2346];
    };
    C5RadioConfig config;
    QueueHandle_t queue = nullptr;
    bool initialized = false, started = false, own_event_loop = false;
    std::uint16_t sequence = 0;
    std::atomic<std::uint32_t> dropped {0};
    static Impl* active;
    static std::mutex callback_mutex;
    explicit Impl(C5RadioConfig c) : config(c) {}
    static void receive(void* buffer, wifi_promiscuous_pkt_type_t type) {
        if (!buffer || type != WIFI_PKT_DATA) return;
        const auto* packet = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
        if (packet->rx_ctrl.rx_state != 0) return;
        // esp_wifi_he_types.h documents sig_len on this chip as "the length of the
        // reception MPDU", not "MPDU + FCS" as older-chip ESP-IDF documentation
        // states; measured on real hardware, it is consistently 4 bytes longer than
        // the actual frame, and those 4 trailing bytes are a fixed, content-independent
        // value (00 00 99 00), not a real, software-recoverable FCS. This promiscuous
        // filter never sets WIFI_PROMIS_FILTER_MASK_FCSFAIL, so the frame itself has
        // already passed a real hardware FCS check by the time it reaches this callback
        // -- see ports/esp_idf/tools/radio_pair.py's docstring for the full evidence.
        const auto length = packet->rx_ctrl.sig_len;
        std::lock_guard<std::mutex> lock(callback_mutex);
        if (!active || !active->queue) return;
        if (length < 38 || length > sizeof(Raw::bytes)) { ++active->dropped; return; }
        Raw raw {};
        raw.length = length; raw.rssi = packet->rx_ctrl.rssi;
        raw.timestamp = packet->rx_ctrl.timestamp;
        std::memcpy(raw.bytes, packet->payload, length);
        if (xQueueSend(active->queue, &raw, 0) != pdTRUE) ++active->dropped;
    }
};
C5Radio::Impl* C5Radio::Impl::active = nullptr;
std::mutex C5Radio::Impl::callback_mutex;
C5Radio::C5Radio(C5RadioConfig c) : impl_(std::make_unique<Impl>(c)) {}
C5Radio::~C5Radio() { stop(); }
esp_err_t C5Radio::start() {
    auto& p = *impl_;
    const auto& c = p.config;
    if (p.initialized) return ESP_ERR_INVALID_STATE;
    if (c.channel_number < 172 || c.channel_number > 184 || c.channel_number % 2 ||
        !std::isfinite(c.transmit_power_dbm) || c.transmit_power_dbm < 2 || c.transmit_power_dbm > 20 ||
        std::floor(c.transmit_power_dbm * 4) != c.transmit_power_dbm * 4 ||
        c.receive_queue_length == 0 || c.receive_queue_length > 32) return ESP_ERR_INVALID_ARG;
    {
        std::lock_guard<std::mutex> lock(Impl::callback_mutex);
        if (Impl::active) return ESP_ERR_INVALID_STATE;
        p.queue = xQueueCreate(c.receive_queue_length, sizeof(Impl::Raw));
        if (!p.queue) return ESP_ERR_NO_MEM;
        Impl::active = &p;
    }
    auto result = esp_event_loop_create_default();
    p.own_event_loop = result == ESP_OK;
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) { stop(); return result; }
    // OpenTrafficMap main/main.c and cmd_sniffer.c establish the FE clock and
    // NON_NGV_10 PHY mode. These private calls are SDK-specific, not ETSI SAPs.
    modem_syscon_ll_enable_fe_40m_clock(&MODEM_SYSCON, true);
    wifi_init_config_t wifi = WIFI_INIT_CONFIG_DEFAULT();
    wifi.nvs_enable = 0;
    result = esp_wifi_init(&wifi);
    if (result != ESP_OK) { stop(); return result; }
    p.initialized = true;
    auto attempt = [&](esp_err_t r) { if (result == ESP_OK) result = r; };
    attempt(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    attempt(esp_wifi_set_mode(WIFI_MODE_STA));
    if (result == ESP_OK) { result = esp_wifi_start(); p.started = result == ESP_OK; }
    if (result != ESP_OK) { stop(); return result; }
    attempt(esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY));
    attempt(esp_wifi_set_ps(WIFI_PS_NONE));
    attempt(esp_wifi_set_max_tx_power(static_cast<std::int8_t>(c.transmit_power_dbm * 4)));
    wifi_promiscuous_filter_t filter {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
    attempt(esp_wifi_set_promiscuous_filter(&filter));
    attempt(esp_wifi_set_promiscuous_rx_cb(Impl::receive));
    attempt(esp_wifi_set_promiscuous(true));
    if (result != ESP_OK) { stop(); return result; }
    phy_11p_set(1, 0); // 10 MHz; never infer PHY width from WIFI_BW20 below.
    phy_change_channel(5000 + 5 * c.channel_number, 1, 0, 0);
    return ESP_OK;
}
void C5Radio::stop() {
    if (!impl_) return;
    auto& p = *impl_;
    if (p.started) esp_wifi_set_promiscuous(false);
    {
        std::lock_guard<std::mutex> lock(Impl::callback_mutex);
        if (Impl::active == &p) Impl::active = nullptr;
        if (p.queue) { vQueueDelete(p.queue); p.queue = nullptr; }
    }
    if (p.started) esp_wifi_stop();
    if (p.initialized) esp_wifi_deinit();
    if (p.own_event_loop) esp_event_loop_delete_default();
    p.started = p.initialized = p.own_event_loop = false;
}
Result C5Radio::request(AlDataRequest request) {
    auto& p = *impl_;
    if (!p.started) return Result::rejected;
    if (!p.config.laboratory_transmission) return Result::unsupported;
    // Reject controls this fixed-channel backend cannot honour. In particular,
    // do not silently reinterpret an AL_DATA bandwidth or transceiver mode.
    if (request.bandwidth_mhz != 10 || request.channel_number != p.config.channel_number ||
        request.transceiver_id != 0 || request.transceiver_mode || request.datastream_id ||
        request.transmit_power_dbm != p.config.transmit_power_dbm) return Result::unsupported;
    constexpr wifi_phy_rate_t rates[] = {WIFI_PHY_RATE_6M, WIFI_PHY_RATE_9M, WIFI_PHY_RATE_12M,
        WIFI_PHY_RATE_18M, WIFI_PHY_RATE_24M, WIFI_PHY_RATE_36M, WIFI_PHY_RATE_48M, WIFI_PHY_RATE_54M};
    const auto index = static_cast<unsigned>(request.mcs);
    if (index >= std::size(rates)) return Result::invalid_argument;
    vanetza::ByteBuffer bytes;
    const auto encoded = its_g5::encode_frame(request, p.sequence, bytes);
    if (encoded != Result::accepted) return encoded;
    p.sequence = (p.sequence + 1) & 4095;
    wifi_tx_rate_config_t rate {};
    rate.phymode = WIFI_PHY_MODE_11A; rate.rate = rates[index];
    // Legacy OFDM rate identifiers are halved by the 10 MHz PHY mode.
    // The driver consumes the frame synchronously into its own ebuf.
    const auto result = esp_wifi_80211_tx_custom(WIFI_IF_STA, bytes.data(), bytes.size(), false,
                                                &rate, WIFI_BAND_5G, WIFI_BW20);
    return result == ESP_OK ? Result::accepted : result == ESP_ERR_NO_MEM ? Result::resource_limit : Result::rejected;
}
void C5Radio::poll(const Receive& receive, const Capture& capture) {
    auto& p = *impl_;
    if (!p.queue) return;
    Impl::Raw raw {};
    // Bound work per poll even if the radio continuously fills the queue.
    for (unsigned i = 0; i < p.config.receive_queue_length && xQueueReceive(p.queue, &raw, 0) == pdTRUE; ++i) {
        if (capture) capture(vanetza::ByteBuffer(raw.bytes, raw.bytes + raw.length), raw.rssi, raw.timestamp);
        AlDataIndication ind;
        if (its_g5::decode_frame(raw.bytes, raw.length, true, ind) != Result::accepted) continue;
        ind.channel_number = p.config.channel_number;
        ind.received_power_dbm = raw.rssi;
        // The SDK does not provide channel-busy time here. CBR remains absent;
        // counting received packets would not be a valid CBR measurement.
        if (receive) receive(std::move(ind));
    }
}
std::uint32_t C5Radio::dropped_frames() const { return impl_->dropped.load(); }
}
