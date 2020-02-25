add_executable(client client.cpp)
target_link_libraries(client PRIVATE ohc::ohc CLI11::CLI11)
