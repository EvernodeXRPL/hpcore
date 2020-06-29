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

# We have 2 executable build outputs: appbill and hpcore


#-------appbill-------

add_executable(appbill
    src/bill/appbill.cpp
)

#-------hpcore-------

add_executable(hpcore
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/sc.cpp
    src/bill/corebill.cpp
    src/hpfs/h32.cpp
    src/hpfs/hpfs.cpp
    src/comm/comm_session.cpp
    src/comm/comm_server.cpp
    src/comm/comm_client.cpp
    src/msg/fbuf/common_helpers.cpp
    src/msg/fbuf/p2pmsg_helpers.cpp
    src/msg/fbuf/ledger_helpers.cpp
    src/msg/json/usrmsg_json.cpp
    src/msg/bson/usrmsg_bson.cpp
    src/msg/usrmsg_parser.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
    src/usr/read_req.cpp
    src/cons/cons.cpp
    src/cons/ledger_handler.cpp
    src/state/state_sync.cpp
    src/state/state_serve.cpp
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
    ${CMAKE_DL_LIBS} # Needed for stacktrace support
)
add_dependencies(hpcore
    appbill
)

add_custom_command(TARGET hpcore POST_BUILD
    # COMMAND strip ./build/hpcore
    # COMMAND strip ./build/appbill
    COMMAND cp ./test/bin/websocketd ./test/bin/websocat ./test/bin/hpfs ./build/
)
    
target_precompile_headers(hpcore PUBLIC src/pchheader.hpp)

# Create docker image from hpcore build output with 'make docker'
# Requires docker to be runnable without 'sudo'
add_custom_target(docker
  COMMAND mkdir -p ./test/local-cluster/bin
  COMMAND cp ./build/hpcore ./build/appbill ./test/local-cluster/bin/
  COMMAND cp ./test/bin/fusermount3 ./test/bin/libfuse3.so.3 ./test/bin/libb2.so.1 ./test/bin/websocketd ./test/bin/websocat ./test/bin/hpfs ./test/local-cluster/bin/
  COMMAND docker build -t hpcore:latest ./test/local-cluster
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)
