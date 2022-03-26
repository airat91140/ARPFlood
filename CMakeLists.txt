cmake_minimum_required(VERSION 3.16)
project(network4 C)

set(CMAKE_C_STANDARD 99)

add_executable(network4 main.c)

target_link_libraries(network4 pcap)


