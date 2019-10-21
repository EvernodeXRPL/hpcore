cmake_minimum_required(VERSION 3.2)
project(HPCore)

add_definitions("-std=c++17" "-DBOOST_LOG_DYN_LINK")
find_package(Boost REQUIRED COMPONENTS system log)

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
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_LOG_LIBRARY}
    stdc++fs
    pthread
    protobuf.a
)