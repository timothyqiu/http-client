add_executable(client cli.cpp)

target_link_libraries(client PRIVATE ohc::ohc CLI11::CLI11 spdlog::spdlog)
