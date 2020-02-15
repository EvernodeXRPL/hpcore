#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "comm_session.hpp"

namespace comm
{

class comm_server
{
    pid_t websocketd_pid = 0;
    int firewall_out = -1; // at some point we may want to listen for firewall_in but at the moment unimplemented
    std::thread domain_sock_listener_thread;
    bool should_stop_listening = false;

    int open_domain_socket(const char *domain_socket_name);
    void listen_domain_socket(
        const int socket_fd, const SESSION_TYPE session_type, const SESSION_MODE mode,
        std::mutex &sessions_mutex, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size);
    int start_websocketd_process(const uint16_t port, const char *domain_socket_name);
    int poll_fds(pollfd *pollfds, const int socket_fd, const std::unordered_map<int, comm_session> &clients);

    void check_for_new_connection(
        std::unordered_map<int, comm_session> &clients, std::mutex &sessions_mutex, const int socket_fd,
        const SESSION_TYPE session_type, const SESSION_MODE mode, const uint64_t (&metric_thresholds)[4]);

    void attempt_client_read(
        bool &should_disconnect, comm_session &session, std::unordered_map<int, uint16_t> &expected_msg_sizes,
        const int fd, const uint64_t max_msg_size);

    int16_t get_binary_msg_read_len(std::unordered_map<int, uint16_t> &expected_msg_sizes, const int fd, const size_t available_bytes);

    // If the fd supplied was produced by accept()ing unix domain socket connection
    // the process at the other end is inspected for CGI environment variables
    // and the REMOTE_ADDR variable is returned as std::string, otherwise empty string
    std::string get_cgi_ip(const int fd);

public:
    // Start accepting incoming connections
    int start(
        const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type, const SESSION_MODE mode,
        std::mutex &sessions_mutex, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size);
    void stop();
    void firewall_ban(std::string_view ip, const bool unban);
};

} // namespace comm

#endif
