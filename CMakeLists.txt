cmake_minimum_required(VERSION 3.16)
project(hpcore)

# Force build type to Release build.
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result -Wreturn-type")

# We have 2 executable build outputs: appbill and hpcore


#-------appbill-------

add_executable(appbill
    src/bill/appbill.cpp
)

#-------hpcore-------

add_executable(hpcore
    src/util/util.cpp
    src/util/rollover_hashset.cpp
    src/util/ttl_set.cpp
    src/util/buffer_store.cpp
    src/util/merkle_hash_tree.cpp
    src/util/h32.cpp
    src/unl.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/bill/corebill.cpp
    src/hpfs/hpfs_mount.cpp
    src/hpfs/hpfs_serve.cpp
    src/hpfs/hpfs_sync.cpp
    src/sc/contract_mount.cpp
    src/sc/contract_serve.cpp
    src/sc/contract_sync.cpp
    src/sc/sc.cpp
    src/comm/comm_session.cpp
    src/msg/fbuf/common_helpers.cpp
    src/msg/fbuf/ledger_helpers.cpp
    src/msg/fbuf/p2pmsg_conversion.cpp
    src/msg/json/controlmsg_json.cpp
    src/msg/controlmsg_parser.cpp
    src/msg/json/usrmsg_json.cpp
    src/msg/bson/usrmsg_bson.cpp
    src/msg/usrmsg_parser.cpp
    src/p2p/peer_comm_server.cpp
    src/p2p/peer_comm_session.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/self_node.cpp
    src/p2p/p2p.cpp
    src/usr/user_comm_session.cpp
    src/usr/user_session_handler.cpp
    src/usr/input_nonce_map.cpp
    src/usr/usr.cpp
    src/usr/read_req.cpp
    src/ledger/sqlite.cpp
    src/ledger/ledger_mount.cpp
    src/ledger/ledger_sync.cpp
    src/ledger/ledger_serve.cpp
    src/ledger/ledger.cpp
    src/consensus.cpp
    src/main.cpp
)
target_link_libraries(hpcore
    libsodium.a
    pthread
    libblake3.so
    libboost_stacktrace_backtrace.a
    backtrace
    sqlite3
    ${CMAKE_DL_LIBS} # Needed for stacktrace support
)
add_dependencies(hpcore
    appbill
)

add_custom_command(TARGET hpcore POST_BUILD
    # COMMAND strip ./build/hpcore
    # COMMAND strip ./build/appbill
    COMMAND cp ./test/bin/hpws ./test/bin/hpfs ./build/
)
    
target_precompile_headers(hpcore PUBLIC src/pchheader.hpp)

# Create docker image from hpcore build output with 'make docker'
# Requires docker to be runnable without 'sudo'
add_custom_target(docker
  COMMAND mkdir -p ./test/local-cluster/bin
  COMMAND cp ./build/hpcore ./build/appbill ./test/local-cluster/bin/
  COMMAND cp ./test/bin/fusermount3 ./test/bin/libfuse3.so.3 ./test/bin/libblake3.so ./test/bin/hpws ./test/bin/hpfs ./test/local-cluster/bin/
  COMMAND docker build -t hpcore:latest ./test/local-cluster
)
set_target_properties(docker PROPERTIES EXCLUDE_FROM_ALL TRUE)
add_dependencies(docker hpcore)
