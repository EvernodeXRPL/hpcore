cmake_minimum_required(VERSION 3.16)
project(HPCore)

# Check for gold linker for faster linking time.
execute_process(COMMAND ${CMAKE_CXX_COMPILER} -fuse-ld=gold -Wl -ldl,--version OUTPUT_VARIABLE stdout ERROR_QUIET)
if("${stdout}" MATCHES "GNU gold")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fuse-ld=gold")
else()
    message(WARNING "GNU gold linker isn't available, using the default system linker.")
endif()

add_definitions("-std=c++17 -ldl")  #-ldl to support printing stack trace at runtime
set(CMAKE_CXX_FLAGS_DEBUG  "-g")    # ensure debug symbols are added
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

# Using buildtype MinSizeRel for smaller build outputs.
#set(CMAKE_BUILD_TYPE "MinSizeRel" FORCE)

link_directories(/usr/local/lib)

add_library(hpsupport
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
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
    ${CMAKE_DL_LIBS}
)

add_library(hpstatefs
    src/statefs/hasher.cpp
    src/statefs/state_common.cpp
    src/statefs/hashmap_builder.cpp
    src/statefs/hashtree_builder.cpp
    src/statefs/state_restore.cpp
    src/statefs/state_store.cpp
)
target_link_libraries(hpstatefs hpsupport)

add_library(hpproc
    src/proc/proc.cpp
)
target_link_libraries(hpproc hpsupport hpstatefs)

add_library(hpbill
    src/bill/corebill.cpp
)
target_link_libraries(hpbill hpsupport)

add_library(hpsock
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_message.cpp
    src/sock/socket_session.cpp
    src/sock/socket_session_lambda.cpp
)
target_link_libraries(hpsock hpsupport hpbill)

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
target_link_libraries(hpcons hpsupport hpproc hpp2p hpusr)

add_executable(hpcore
    src/main.cpp
)
target_link_libraries(hpcore
    hpsupport
    hpproc
    hpbill
    hpschema
    hpsock
    hpp2p
    hpusr
    hpcons
)

add_executable(hpstatemon
    src/statefs/state_monitor/fusefs.cpp
    src/statefs/state_monitor/state_monitor.cpp
    src/statefs/hasher.cpp
    src/statefs/state_common.cpp
)
target_link_libraries(hpstatemon
    hpsupport
    libfuse3.so.3
)

add_dependencies(hpcore
    hpstatemon
)
    
target_precompile_headers(hpsupport PUBLIC src/pchheader.hpp)
target_precompile_headers(hpcore REUSE_FROM hpsupport)
target_precompile_headers(hpsock REUSE_FROM hpsupport)
target_precompile_headers(hpschema REUSE_FROM hpsupport)
target_precompile_headers(hpp2p REUSE_FROM hpsupport)
target_precompile_headers(hpusr REUSE_FROM hpsupport)
target_precompile_headers(hpcons REUSE_FROM hpsupport)
target_precompile_headers(hpstatemon REUSE_FROM hpsupport)

# Create docker image from hpcore build output with 'make docker'
# Requires docker to be runnable without 'sudo'
add_custom_target(docker
  COMMAND strip ./build/hpcore
  COMMAND docker build -t hpcore:latest .
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)
