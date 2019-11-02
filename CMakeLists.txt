cmake_minimum_required(VERSION 3.16)
project(HPCore)

add_definitions("-std=c++17")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)
set(CMAKE_BUILD_TYPE "MinSizeRel" FORCE)

link_directories(/usr/local/lib)

add_library(hpsupport
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/proc.cpp
)
target_link_libraries(hpsupport
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

add_library(hpsock
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_message.cpp
    src/sock/socket_monitor.cpp
    src/sock/socket_session.cpp
    src/sock/socket_session_lambda.cpp
)
target_link_libraries(hpsock hpsupport)

add_library(hpschema
    src/fbschema/common_helpers.cpp
    src/fbschema/p2pmsg_helpers.cpp
    src/fbschema/ledger_helpers.cpp
    src/jsonschema/usrmsg_helpers.cpp
)
target_link_libraries(hpschema hpsupport)

add_library(hpp2p
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
)
target_link_libraries(hpp2p hpsupport hpsock hpschema)

add_library(hpusr
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
)
target_link_libraries(hpusr hpsupport hpsock hpschema)

add_library(hpcons
    src/cons/cons.cpp
    src/cons/ledger_handler.cpp
)
target_link_libraries(hpcons hpsupport hpp2p hpusr)

add_executable(hpcore
    src/main.cpp
)
target_link_libraries(hpcore
    hpsupport
    hpschema
    hpsock
    hpp2p
    hpusr
    hpcons
)

target_precompile_headers(hpsupport PUBLIC src/pchheader.hpp)
target_precompile_headers(hpcore REUSE_FROM hpsupport)
target_precompile_headers(hpsock REUSE_FROM hpsupport)
target_precompile_headers(hpschema REUSE_FROM hpsupport)
target_precompile_headers(hpp2p REUSE_FROM hpsupport)
target_precompile_headers(hpusr REUSE_FROM hpsupport)
target_precompile_headers(hpcons REUSE_FROM hpsupport)

add_custom_target(docker
  COMMAND strip ./build/hpcore
  COMMAND docker build -t hpcore:latest .
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)