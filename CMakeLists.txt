cmake_minimum_required(VERSION 3.21)
project(privacy-protection-messenger)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lssl -lcrypto -lpthread -lsoter -lthemis -lmariadbcpp")

add_compile_definitions(VERSION="${PACKAGE_VERSION}" VAR_DIRECTORY="${VAR_DIRECTORY}")

add_executable(privacy-protection-messenger main.cpp)
