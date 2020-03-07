cmake_minimum_required(VERSION 3.11)

project(HttpClient LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}")

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  set(CMAKE_CXX_EXTENSIONS OFF)

  include(CTest)

  find_program(CCACHE_PROGRAM ccache)
  if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(mbedtls REQUIRED)
find_package(CLI11 REQUIRED)
find_package(spdlog REQUIRED)

add_subdirectory(src)
add_subdirectory(apps)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
  find_package(Catch2 REQUIRED)
  find_package(rapidjson REQUIRED)
  add_subdirectory(tests)
endif()
