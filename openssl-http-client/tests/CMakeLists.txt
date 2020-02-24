FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v2.11.1
)
FetchContent_MakeAvailable(catch2)

add_executable(test-ohc test_ohc.cpp)
target_link_libraries(test-ohc PRIVATE ohc::ohc Catch2::Catch2)

add_test(NAME MainTest COMMAND test-ohc)
