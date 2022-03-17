cmake_minimum_required(VERSION 3.21)
project(privacy-protection-messenger)

set(CMAKE_CXX_STANDARD 20)

add_compile_definitions(VERSION="${PACKAGE_VERSION}")

add_executable(privacy-protection-messenger main.cpp)
