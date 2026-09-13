#include <vanetza_idf/access.hpp>
#include <esp_log.h>
#if VIDF_NETWORK
#include <vanetza_idf/stack.hpp>
#endif

/** Replace this adapter with a hardware driver or test lower port. No radio is
 * enabled by this integration example. A non-existent device rejects requests.
 */
class ExampleAccess : public vanetza_idf::Access {
public:
    vanetza_idf::Result request(vanetza_idf::AlDataRequest) override {
        return vanetza_idf::Result::unsupported;
    }
};

extern "C" void app_main() {
    ExampleAccess access;
#if VIDF_NETWORK
    vanetza::ManualRuntime runtime;
    vanetza_idf::StackConfig config;
    config.mib.vanetzaDisableBeaconing = true;
    vanetza_idf::Stack stack(config, runtime, access);
    ESP_LOGI("vanetza-idf", "Network profile ready; inject position, time, security and Access adapter");
    // The application event loop owns stack lifetime. In production, keep this
    // object alive while processing queued sensor, receive and timer events.
#else
    vanetza_idf::AccessStack stack(access);
    ESP_LOGI("vanetza-idf", "Access profile ready; inject AL_DATA.request primitives");
#endif
}
