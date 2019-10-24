cmake_minimum_required(VERSION 3.2)
project(HPCore)

add_definitions("-std=c++17")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)

add_executable(hpcore
    src/p2p/peer_message_handler.cpp
    src/p2p/peer_session_handler.cpp
    src/p2p/p2p.cpp
    src/cons/cons.cpp
    src/util.cpp
    src/crypto.cpp
    src/conf.cpp
    src/hplog.cpp
    src/proc.cpp
    src/usr/user_session_handler.cpp
    src/usr/usr.cpp
    src/main.cpp
)

add_custom_target(release
  COMMAND cmake -DCMAKE_BUILD_TYPE=RELEASE .
  COMMAND make hpcore
  COMMAND strip ./build/hpcore
  COMMAND docker build -t hpcore:latest .
)
set_target_properties(release PROPERTIES EXCLUDE_FROM_ALL TRUE)

target_link_libraries(hpcore
    libsodium.a
    libboost_system.a
    libboost_thread.a
    libboost_log.a
    libboost_log_setup.a
    libboost_filesystem.a
    stdc++fs
    pthread
    crypto
    ssl
)