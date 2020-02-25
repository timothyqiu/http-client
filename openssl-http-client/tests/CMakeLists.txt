FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v2.11.1
)
FetchContent_MakeAvailable(catch2)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/contrib)

add_executable(test-library test_library.cpp)
target_link_libraries(test-library PRIVATE ohc::ohc Catch2::Catch2)

include(Catch)
catch_discover_tests(test-library)
