set(HEADER_LIST
  "${OpenSslHttpClient_SOURCE_DIR}/include/ohc/buffer.hpp"
  "${OpenSslHttpClient_SOURCE_DIR}/include/ohc/http.hpp"
  "${OpenSslHttpClient_SOURCE_DIR}/include/ohc/session.hpp"
  "${OpenSslHttpClient_SOURCE_DIR}/include/ohc/url.hpp"
)

add_library(ohc buffer.cpp http.cpp session.cpp url.cpp ${HEADER_LIST})
add_library(ohc::ohc ALIAS ohc)

target_include_directories(ohc PUBLIC ../include)
target_compile_features(ohc PUBLIC cxx_std_17)
target_link_libraries(ohc PRIVATE spdlog::spdlog)
