add_executable(test-library main.cpp http.cpp url.cpp)
target_link_libraries(test-library PRIVATE ohc::ohc Catch2::Catch2)

include(Catch)
catch_discover_tests(test-library)
