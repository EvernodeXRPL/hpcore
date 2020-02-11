#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "comm_session.hpp"

namespace comm
{

class comm_server
{
    pid_t websocketd_pid;
    std::thread domain_sock_listener_thread;
    std::thread domain_sock_reader_thread;
    std::unordered_map<int, comm_session> domain_sock_clients;

    int open_domain_socket(const char *domain_socket_name);
    void listen_domain_socket(const int socket_fd, comm_session_handler &sess_handler);
    void read_client_sockets();
    int start_websocketd_process(const uint16_t port, const char *domain_socket_name);

public:
    // Start accepting incoming connections
    int start(const uint16_t port, const char *domain_socket_name, comm_session_handler &sess_handler);
};


} // namespace comm

#endif