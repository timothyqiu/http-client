add_executable(client
  cli.cpp
  openssl/buffer.hpp openssl/buffer.cpp
  openssl/exceptions.hpp openssl/exceptions.cpp
  openssl/session.hpp openssl/session.cpp
)
target_link_libraries(client PRIVATE ohc::ohc OpenSSL::SSL CLI11::CLI11 spdlog::spdlog)

# temporary mbedtls scratch program
add_executable(mbedtls-demo
  mbedtls/demo.cpp
  mbedtls/buffer.hpp mbedtls/buffer.cpp
  mbedtls/exceptions.hpp mbedtls/exceptions.cpp
)
target_link_libraries(mbedtls-demo PRIVATE ohc::ohc MbedTLS::TLS MbedTLS::Crypto MbedTLS::X509 spdlog::spdlog)
