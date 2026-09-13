#include <cstdio>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
int vidf_test_main();
void run_hil_server();
extern "C" void app_main() {
    std::puts("vanetza-idf component tests beginning");
    const int result = vidf_test_main();
    std::printf("VIDF_TEST_RESULT=%d\n", result);
    if (result == 0) run_hil_server();
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}
