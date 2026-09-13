#include <cstdio>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
int vidf_test_main();
void run_hil_server();
extern "C" void app_main() {
    // The ESP32-C5 ROM UART0 clock repair for warm resets is applied by the component
    // itself (ports/esp_idf/src/esp32c5_rom_uart_clock.c) before app_main runs.
    std::puts("vanetza-idf component tests beginning");
    // The security tests run about a minute of software ECDSA without yielding; give the
    // idle-task watchdog that long instead of interleaving its reports with the output.
    esp_task_wdt_config_t watchdog = {};
    watchdog.timeout_ms = 300000;
    watchdog.idle_core_mask = (1 << portNUM_PROCESSORS) - 1;
    watchdog.trigger_panic = false;
    esp_task_wdt_reconfigure(&watchdog);
    const int result = vidf_test_main();
    std::printf("VIDF_TEST_RESULT=%d\n", result);
    if (result == 0) run_hil_server();
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}
