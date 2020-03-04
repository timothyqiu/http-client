add_executable(openssl-client
  cli.cpp
  openssl/buffer.hpp openssl/buffer.cpp
  openssl/core.hpp openssl/core.cpp
  openssl/exceptions.hpp openssl/exceptions.cpp
  openssl/session.hpp openssl/session.cpp
)
target_compile_definitions(openssl-client PRIVATE USE_OPENSSL)
target_link_libraries(openssl-client PRIVATE ohc::ohc OpenSSL::SSL CLI11::CLI11 spdlog::spdlog)

add_executable(mbedtls-client
  cli.cpp
  mbedtls/buffer.hpp mbedtls/buffer.cpp
  mbedtls/core.hpp mbedtls/core.cpp
  mbedtls/exceptions.hpp mbedtls/exceptions.cpp
  mbedtls/session.hpp mbedtls/session.cpp
)
target_compile_definitions(mbedtls-client PRIVATE USE_MBEDTLS)
target_link_libraries(mbedtls-client PRIVATE ohc::ohc MbedTLS::TLS MbedTLS::Crypto MbedTLS::X509 CLI11::CLI11 spdlog::spdlog)
