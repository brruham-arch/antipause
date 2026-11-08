cmake_minimum_required(VERSION 3.10)
project(antipause CXX)
add_library(antipause SHARED src/antipause.cpp)
target_link_libraries(antipause log dl)
