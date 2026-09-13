idf_component_register(SRCS "main.cpp" "hil_server.cpp"
    "../../../ports/esp_idf/tests/test_main.cpp"
    "../../../ports/esp_idf/tests/hil_sut.cpp"
    REQUIRES vanetza-idf esp_driver_usb_serial_jtag)
target_compile_definitions(${COMPONENT_LIB} PRIVATE main=vidf_test_main)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
