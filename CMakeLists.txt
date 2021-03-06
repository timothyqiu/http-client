cmake_minimum_required(VERSION 3.11)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}")

project(HttpClient LANGUAGES CXX)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  set(HTTPCLIENT_MASTER_PROJECT ON)

  set(CMAKE_CXX_EXTENSIONS OFF)

  if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
    set(CMAKE_BUILD_TYPE
        RelWithDebInfo
        CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel"
                                                 "RelWithDebInfo")
  endif()

  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(STATUS "IPO is not supported: ${output}")
  endif()

  include(CTest)

  find_program(CCACHE_PROGRAM ccache)
  if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  endif()
else()
  set(HTTPCLIENT_MASTER_PROJECT OFF)
endif()

option(HTTPCLIENT_INSTALL "Generate the install target" ${HTTPCLIENT_MASTER_PROJECT})

if(HTTPCLIENT_INSTALL)
  include(GNUInstallDirs)
  list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
       "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}" isSystemDir)
  if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  endif("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()

add_library(project_warnings INTERFACE)
target_compile_options(
  project_warnings
  INTERFACE $<$<CXX_COMPILER_ID:MSVC>:
            /W4
            /w14640>
            $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:
            -Wall
            -Wextra
            -pedantic
            -Wshadow
            -Wsign-conversion
            -Wswitch-enum
            -Wnon-virtual-dtor>)

find_package(OpenSSL REQUIRED)
find_package(mbedtls REQUIRED)
find_package(CLI11 REQUIRED)
find_package(spdlog REQUIRED)

# CLI11 uses std::filesystem in C++17, may require extra std-libraries depends on the
# compiler. Just disable the use of std::filesystem here.
target_compile_definitions(CLI11::CLI11 INTERFACE CLI11_HAS_FILESYSTEM=0)

add_subdirectory(src)
add_subdirectory(apps)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
  find_package(Catch2 REQUIRED)
  find_package(nlohmann_json REQUIRED)
  add_subdirectory(tests)
endif()
