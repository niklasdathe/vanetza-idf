#include <vanetza_idf/hil.hpp>
#include "../../../ports/esp_idf/tests/hil_sut.hpp"
#include <driver/usb_serial_jtag.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <algorithm>
#include <memory>
#if CONFIG_VANETZA_IDF_RADIO_C5
#include <vanetza_idf/c5_radio.hpp>
#endif

void run_hil_server() {
    using namespace vanetza_idf;
    using vanetza::ByteBuffer;
    usb_serial_jtag_driver_config_t config {};
    config.rx_buffer_size = 8192; config.tx_buffer_size = 8192;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
    hil::Decoder decoder;
    vidf_test::Sut sut;
#if CONFIG_VANETZA_IDF_RADIO_C5
    std::unique_ptr<C5Radio> radio;
    std::uint16_t radio_channel = 180;
#endif
    auto handle = [&](hil::Frame frame) {
        if (frame.channel != hil::Channel::diagnostic) return;
        const auto& in = frame.payload;
        ByteBuffer reply;
#if CONFIG_VANETZA_IDF_RADIO_C5
        if (in.size() == 4 && in[0] == 3 && in[3] <= 1) {
            radio.reset();
            C5RadioConfig rc;
            rc.channel_number = (in[1] << 8) | in[2];
            radio_channel = rc.channel_number;
            rc.laboratory_transmission = in[3] != 0;
            radio = std::make_unique<C5Radio>(rc);
            const auto error = radio->start();
            if (error != ESP_OK) radio.reset();
            reply = {static_cast<std::uint8_t>(error == ESP_OK ? Result::accepted : Result::rejected), 0};
        } else if (in.size() > 15 && in[0] == 4 && radio) {
            AlDataRequest request;
            std::copy(in.begin() + 1, in.begin() + 7, request.source.octets.begin());
            std::copy(in.begin() + 7, in.begin() + 13, request.destination.octets.begin());
            request.priority = in[13]; request.mcs = static_cast<OfdmMcs>(in[14]);
            request.transmit_power_dbm = 10.0;
            request.channel_number = radio_channel;
            request.data.assign(in.begin() + 15, in.end());
            reply = {static_cast<std::uint8_t>(radio->request(std::move(request))), 0};
        } else if (in.size() == 1 && in[0] == 5 && radio) {
            reply = {static_cast<std::uint8_t>(Result::accepted), 0};
            radio->poll({}, [&](const ByteBuffer& bytes, int rssi, std::uint32_t time) {
                if (reply.size() + bytes.size() + 8 > 4096) {
                    reply[0] = static_cast<std::uint8_t>(Result::resource_limit); return;
                }
                ++reply[1]; reply.push_back(3);
                reply.push_back((bytes.size() + 5) >> 8); reply.push_back(bytes.size() + 5);
                reply.push_back(static_cast<std::uint8_t>(rssi));
                for (int shift = 24; shift >= 0; shift -= 8) reply.push_back(time >> shift);
                reply.insert(reply.end(), bytes.begin(), bytes.end());
            });
        } else if (in.size() == 1 && in[0] == 6) {
            radio.reset();
            reply = {static_cast<std::uint8_t>(Result::accepted), 0};
        } else
#endif
            reply = sut.execute(in);
        const auto encoded = hil::encode({hil::Channel::diagnostic, frame.sequence, std::move(reply)});
        std::size_t sent = 0;
        while (sent < encoded.size()) {
            const int count = usb_serial_jtag_write_bytes(encoded.data() + sent,
                encoded.size() - sent, pdMS_TO_TICKS(2000));
            if (count <= 0) break; // The host detects an incomplete reply by timeout/CRC.
            sent += count;
        }
    };
    std::uint8_t bytes[256];
    for (;;) {
        const int count = usb_serial_jtag_read_bytes(bytes, sizeof(bytes), pdMS_TO_TICKS(20));
        if (count > 0) decoder.feed(bytes, count, handle);
    }
}
