cmake_minimum_required(VERSION 3.2)
project(HPCore)

add_definitions("-std=c++17")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

add_executable(hpcore
    src/main.cpp
    src/conf.cpp
    src/crypto.cpp
    src/proc.cpp
    src/usr/usr.cpp
    src/usr/user_session_handler.cpp
    src/util.cpp
    src/p2p/message.pb.cc
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_session.cpp
)

target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_filesystem.a
    pthread
    protobuf.a
)