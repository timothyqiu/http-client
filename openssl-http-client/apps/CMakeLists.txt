add_executable(client
  cli.cpp
  openssl/buffer.hpp openssl/buffer.cpp
  openssl/exceptions.hpp openssl/exceptions.cpp
  openssl/session.hpp openssl/session.cpp
)
target_link_libraries(client PRIVATE ohc::ohc OpenSSL::SSL CLI11::CLI11 spdlog::spdlog)
