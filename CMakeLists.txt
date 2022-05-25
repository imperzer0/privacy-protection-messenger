cmake_minimum_required(VERSION 3.21)
project(privacy-protection-messenger)

set(CMAKE_CXX_STANDARD 20)

if (DEFINED PACKAGE_VERSION)
    add_compile_definitions(VERSION="${PACKAGE_VERSION}")
endif ()

if (DEFINED VAR_DIRECTORY)
    add_compile_definitions(VAR_DIRECTORY="${VAR_DIRECTORY}")
endif ()

if (DEFINED APPNAME)
    add_compile_definitions(MESSENGER_NAME="${APPNAME}")
endif ()

if (DEFINED CFG_DIR)
    add_compile_definitions(CONFIG_DIR="${CFG_DIR}")
endif ()

add_executable(privacy-protection-messenger main.cpp)

target_link_libraries(privacy-protection-messenger ssl crypto pthread soter themis mariadbcpp lua)