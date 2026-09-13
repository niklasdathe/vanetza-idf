set(_tests "../../../ports/esp_idf/tests")
idf_component_register(SRCS "main.cpp" "hil_server.cpp" "${_tests}/test_main.cpp" "${_tests}/hil_sut.cpp"
    REQUIRES vanetza-idf esp_driver_usb_serial_jtag)
if(CONFIG_VANETZA_IDF_SECURITY)
    target_sources(${COMPONENT_LIB} PRIVATE "${_tests}/test_backend_kat.cpp" "${_tests}/test_security_entity.cpp"
        "${_tests}/test_trust_domain.cpp")
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE main=vidf_test_main)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
