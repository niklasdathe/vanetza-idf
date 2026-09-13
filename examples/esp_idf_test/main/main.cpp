#include <cstdio>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#if CONFIG_IDF_TARGET_ESP32C5
#include <soc/pcr_reg.h>
#include <soc/soc.h>
#endif
int vidf_test_main();
void run_hil_server();
extern "C" void app_main() {
#if CONFIG_IDF_TARGET_ESP32C5
    // ESP-IDF's C5 system_internal.c documents that ROM UART initialization misses
    // this clock enable; a USB/JTAG-triggered warm reset (esptool, a DTR/RTS toggle)
    // then leaves the next boot's ROM stage waiting forever for PCR_UART0_READY. Done
    // first thing so a failing test run cannot leave the board unflashable until a
    // power cycle (that happened: evidence/security-device-02).
    REG_SET_BIT(PCR_UART0_SCLK_CONF_REG, PCR_UART0_SCLK_EN);
#endif
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
