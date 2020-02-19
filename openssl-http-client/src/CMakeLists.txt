add_executable(client client.cpp)
target_compile_features(client PRIVATE cxx_std_17)
target_link_libraries(client PRIVATE OpenSSL::SSL)
