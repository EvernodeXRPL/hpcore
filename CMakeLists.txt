cmake_minimum_required(VERSION 3.2)
project(HPCore)

add_definitions("-std=c++17")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

add_executable(hpcore
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_session.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/proc.cpp
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
    src/main.cpp
)

target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_filesystem.a
    pthread
    protobuf.a
)