add_executable(client client.cpp openssl.hpp openssl.cpp)
target_link_libraries(client PRIVATE ohc::ohc OpenSSL::SSL CLI11::CLI11 spdlog::spdlog)
