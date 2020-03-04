add_executable(client
  cli.cpp

  openssl/buffer.hpp openssl/buffer.cpp
  openssl/core.hpp openssl/core.cpp
  openssl/exceptions.hpp openssl/exceptions.cpp
  openssl/session.hpp openssl/session.cpp

  mbedtls/buffer.hpp mbedtls/buffer.cpp
  mbedtls/core.hpp mbedtls/core.cpp
  mbedtls/exceptions.hpp mbedtls/exceptions.cpp
  mbedtls/session.hpp mbedtls/session.cpp
)
target_link_libraries(client PRIVATE
  ohc::ohc CLI11::CLI11 spdlog::spdlog
  OpenSSL::SSL
  MbedTLS::TLS MbedTLS::Crypto MbedTLS::X509
)
