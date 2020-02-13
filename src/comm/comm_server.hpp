#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "comm_session.hpp"

namespace comm
{

class comm_server
{
    pid_t websocketd_pid;
    int firewall_out = -1; // at some point we may want to listen for firewall_in but at the moment unimplemented
    std::thread domain_sock_listener_thread;

    int open_domain_socket(const char *domain_socket_name);
    void listen_domain_socket(const int socket_fd, const SESSION_TYPE session_type);
    int start_websocketd_process(const uint16_t port, const char *domain_socket_name);

public:
    // Start accepting incoming connections
    int start(const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type);

    void firewall_ban(std::string_view ip, bool unban);
};

    // If the fd supplied was produced by accept()ing unix domain socket connection
    // the process at the other end is inspected for CGI environment variables
    // and the REMOTE_ADDR variable is returned as std::string, otherwise empty string
    std::string get_cgi_ip(int fd);

} // namespace comm

#endif
