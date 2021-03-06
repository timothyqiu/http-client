set(HEADER_LIST
    "${HttpClient_SOURCE_DIR}/include/ohc/buffer.hpp"
    "${HttpClient_SOURCE_DIR}/include/ohc/http.hpp"
    "${HttpClient_SOURCE_DIR}/include/ohc/session.hpp"
    "${HttpClient_SOURCE_DIR}/include/ohc/session_config.hpp"
    "${HttpClient_SOURCE_DIR}/include/ohc/session_factory.hpp"
    "${HttpClient_SOURCE_DIR}/include/ohc/url.hpp")

add_library(
  ohc
  ${HEADER_LIST}
  buffer.cpp
  http.cpp
  session.cpp
  session_config.cpp
  session_factory.cpp
  url.cpp
  utils.hpp
  utils.cpp
  openssl/buffer.hpp
  openssl/buffer.cpp
  openssl/core.hpp
  openssl/core.cpp
  openssl/exceptions.hpp
  openssl/exceptions.cpp
  openssl/session.hpp
  openssl/session.cpp
  mbedtls/buffer.hpp
  mbedtls/buffer.cpp
  mbedtls/core.hpp
  mbedtls/core.cpp
  mbedtls/exceptions.hpp
  mbedtls/exceptions.cpp
  mbedtls/session.hpp
  mbedtls/session.cpp)
add_library(ohc::ohc ALIAS ohc)

set_target_properties(ohc PROPERTIES PUBLIC_HEADER "${HEADER_LIST}")

target_include_directories(ohc PUBLIC ../include)
target_compile_features(ohc PUBLIC cxx_std_17)
target_link_libraries(ohc PRIVATE project_warnings spdlog::spdlog OpenSSL::OpenSSL
                                  mbedtls::mbedtls)

if(HTTPCLIENT_INSTALL)
  install(TARGETS ohc PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ohc)
endif()
