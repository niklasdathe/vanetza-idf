idf_component_register(SRCS "main.cpp" REQUIRES vanetza-idf esp_timer)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
