cmake_minimum_required(VERSION 3.2)
project(HPCore)

add_definitions("-std=c++17")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)
set(CMAKE_BUILD_TYPE "MinSizeRel" FORCE)

add_executable(hpcore
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/fbschema/common_helpers.cpp
    src/fbschema/p2pmsg_helpers.cpp
    src/fbschema/ledger_helpers.cpp
    src/jsonschema/usrmsg_helpers.cpp
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_session.cpp
    src/sock/socket_monitor.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
    src/proc.cpp
    src/cons/cons.cpp
    src/cons/ledger_handler.cpp
    src/main.cpp
)

add_custom_target(docker
  COMMAND strip ./build/hpcore
  COMMAND docker build -t hpcore:latest .
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)

target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_thread.a
    libboost_log.a
    libboost_log_setup.a
    libboost_filesystem.a
    pthread
    crypto
    ssl
)