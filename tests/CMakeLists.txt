add_executable(test-library main.cpp http.cpp session.cpp url.cpp utils.cpp)
target_link_libraries(test-library PRIVATE ohc::ohc Catch2::Catch2 rapidjson::rapidjson)

include(Catch)
catch_discover_tests(test-library)
