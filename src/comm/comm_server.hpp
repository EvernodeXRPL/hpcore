#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "comm_session.hpp"

namespace comm
{

class comm_server
{
    pid_t websocketd_pid;
    std::thread domain_sock_listener_thread;

    int open_domain_socket(const char *domain_socket_name);
    void listen_domain_socket(const int socket_fd, const SESSION_TYPE session_type);
    int start_websocketd_process(const uint16_t port, const char *domain_socket_name);

public:
    // Start accepting incoming connections
    int start(const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type);
};


} // namespace comm

#endif