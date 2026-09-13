# Kconfig hides this backend on other SoCs; this independent guard also rejects
# forced/stale configurations. The private ABI is qualified per SDK version.
if(NOT IDF_TARGET STREQUAL "esp32c5")
    message(FATAL_ERROR "Integrated ITS-G5 radio requires IDF_TARGET=esp32c5")
endif()
if(NOT IDF_VERSION_MAJOR EQUAL 6 OR NOT IDF_VERSION_MINOR EQUAL 0 OR NOT IDF_VERSION_PATCH EQUAL 2)
    message(FATAL_ERROR "C5 private radio ABI is pinned to ESP-IDF 6.0.2")
endif()
set(_otm_source "${VIDF_PORT}/third_party/otm/main/tx_custom.c")
if(NOT EXISTS "${_otm_source}")
    message(FATAL_ERROR "Initialize the OpenTrafficMap submodule before selecting the C5 radio")
endif()
file(READ "${_otm_source}" _otm)
string(REPLACE "\r\n" "\n" _otm "${_otm}")
string(SHA256 _otm_hash "${_otm}")
if(NOT _otm_hash STREQUAL "cb1dccfef96912ca59275e8a9102f41f56925b94a19d4a4629082aaeb779be1b")
    message(FATAL_ERROR "OpenTrafficMap transmitter differs from the reviewed source revision")
endif()
# Keep the upstream checkout immutable. The sole logic patch preserves the
# actual driver submission result, which upstream discarded. ESP_OK still
# means submission, not independent observation of transmission on air.
string(REPLACE "            ieee80211_post_hmac_tx(eb);"
               "            result = ieee80211_post_hmac_tx(eb);" _otm "${_otm}")
set(_otm_generated "${CMAKE_CURRENT_BINARY_DIR}/otm_tx_custom.c")
file(WRITE "${_otm_generated}" "#include <assert.h>\n#include <stddef.h>\n${_otm}\n_Static_assert(offsetof(x_ebuf_t, txdesc) == 0x38, \"ebuf txdesc offset\");\n_Static_assert(offsetof(x_eb_txdesc_t, rate) == 0x0c, \"txdesc rate offset\");\n")
target_sources(${VIDF_TARGET} PRIVATE "${VIDF_PORT}/src/c5_radio.cpp" "${_otm_generated}")
target_include_directories(${VIDF_TARGET} PRIVATE "${VIDF_PORT}/third_party/otm/main")
