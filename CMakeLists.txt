cmake_minimum_required(VERSION 3.2)

add_definitions("-std=c++17")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

add_executable(hpcore
    src/main.cpp
    src/conf.cpp
    src/crypto.cpp
    src/proc.cpp
    src/shared.cpp
    src/usr/usr.cpp
    src/shared.cpp
)

target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_filesystem.a
)