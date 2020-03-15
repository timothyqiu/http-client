add_executable(client cli.cpp config.hpp config.cpp)

target_link_libraries(client PRIVATE ohc::ohc CLI11::CLI11 spdlog::spdlog)
