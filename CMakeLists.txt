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

# We have 3 executable build outputs: appbill, hpstatemon and hpcore


#-------appbill-------

add_executable(appbill
    src/bill/appbill.cpp
)


#-------hpstatemon-------

add_executable(hpstatemon
    src/statefs/state_monitor/fusefs.cpp
    src/statefs/state_monitor/state_monitor.cpp
    src/statefs/hasher.cpp
    src/statefs/state_common.cpp
)
target_link_libraries(hpstatemon
    libfuse3.so.3
    libsodium.a
    libboost_system.a
    libboost_thread.a
    libboost_filesystem.a
    libboost_stacktrace_backtrace.a
    backtrace
    pthread
    crypto
    ssl
    ${CMAKE_DL_LIBS} # Needed for stacktrace support
)


#-------hpcore-------

add_executable(hpcore
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/proc.cpp
    src/bill/corebill.cpp
    src/statefs/hasher.cpp
    src/statefs/state_common.cpp
    src/statefs/hashmap_builder.cpp
    src/statefs/hashtree_builder.cpp
    src/statefs/state_restore.cpp
    src/statefs/state_store.cpp
    src/sock/socket_client.cpp
    src/sock/socket_server.cpp
    src/sock/socket_message.cpp
    src/sock/socket_session.cpp
    src/sock/socket_session_lambda.cpp
    src/fbschema/common_helpers.cpp
    src/fbschema/p2pmsg_helpers.cpp
    src/fbschema/ledger_helpers.cpp
    src/jsonschema/usrmsg_helpers.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
    src/cons/cons.cpp
    src/cons/ledger_handler.cpp
    src/cons/state_handler.cpp
    src/main.cpp
)
target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_thread.a
    libboost_log.a
    libboost_log_setup.a
    libboost_filesystem.a
    libboost_stacktrace_backtrace.a
    backtrace
    pthread
    crypto
    ssl
    ${CMAKE_DL_LIBS} # Needed for stacktrace support
)
add_dependencies(hpcore
    hpstatemon
    appbill
)

# add_custom_command(TARGET hpcore POST_BUILD
#     COMMAND strip ./build/hpcore
#     COMMAND strip ./build/hpstatemon
#     COMMAND strip ./build/appbill
# )
    
target_precompile_headers(hpstatemon PUBLIC src/pchheader.hpp)
target_precompile_headers(hpcore REUSE_FROM hpstatemon)

# Create docker image from hpcore build output with 'make docker'
# Requires docker to be runnable without 'sudo'
add_custom_target(docker
  COMMAND mkdir -p ./test/local-cluster/bin
  COMMAND cp ./build/hpcore ./build/hpstatemon ./build/appbill ./test/local-cluster/bin/
  COMMAND cp ./test/fusebin/fusermount3 ./test/fusebin/libfuse3.so.3 ./test/local-cluster/bin/
  COMMAND docker build -t hpcore:latest ./test/local-cluster
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)
