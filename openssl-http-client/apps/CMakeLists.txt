add_executable(client cli.cpp http.hpp http.cpp openssl.hpp openssl.cpp)
target_link_libraries(client PRIVATE ohc::ohc OpenSSL::SSL CLI11::CLI11 spdlog::spdlog)
