// ESP32-C5 boot repair, linked into every application that uses this component on
// that target (the component's CMake forces the object in with "-u").
//
// ESP-IDF's esp_system/port/soc/esp32c5/system_internal.c documents that the C5
// ROM's UART initialisation misses the UART0 function clock enable
// (PCR_UART0_SCLK_EN, "does not reset with the UART module") and repairs it inside
// esp_restart(). A reset triggered over USB-Serial/JTAG or JTAG (esptool's
// DTR/RTS toggle, OpenOCD, a debugger) bypasses esp_restart(), so once an
// application has left the bit cleared the next boot's ROM stage waits forever
// for PCR_UART0_READY and the board stays unreachable until a power cycle.
// Setting the bit early in every boot keeps warm resets working regardless of what
// the application does with UART0; the cost is one register write.
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32C5
#include <esp_err.h>
#include <esp_private/startup_internal.h>
#include <soc/pcr_reg.h>
#include <soc/soc.h>

ESP_SYSTEM_INIT_FN(vidf_esp32c5_rom_uart_clock, CORE, BIT(0), 120) {
    REG_SET_BIT(PCR_UART0_SCLK_CONF_REG, PCR_UART0_SCLK_EN);
    return ESP_OK;
}

// Referenced through "-u" so the linker keeps this object and its init entry.
void vidf_esp32c5_rom_uart_clock_link(void) {}
#endif
