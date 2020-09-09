#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "comm_session.hpp"
#include "comm_client.hpp"

namespace comm
{

    class comm_server
    {
        pid_t websocketd_pid = 0;
        int firewall_out = -1;                      // at some point we may want to listen for firewall_in but at the moment unimplemented
        std::thread watchdog_thread;                // Connection watcher thread.
        std::thread message_processor_thread;       // Incoming message processor thread.
        bool should_stop_listening = false;

        int open_domain_socket(const char *domain_socket_name);

        void connection_watchdog(
            const int accept_fd, const SESSION_TYPE session_type, const bool is_binary,
            const uint64_t (&metric_thresholds)[4], const std::set<conf::ip_port_pair> &eq_known_remotes, const uint64_t max_msg_size);

        void message_processor_loop(const SESSION_TYPE session_type);

        int start_websocketd_process(
            const uint16_t port, const char *domain_socket_name,
            const bool is_binary, const bool use_size_header, const uint64_t max_msg_size);

        int poll_fds(pollfd *pollfds, const int accept_fd, const std::unordered_map<int, comm_session> &sessions);

        void check_for_new_connection(
            std::unordered_map<int, comm_session> &sessions, const int accept_fd,
            const SESSION_TYPE session_type, const bool is_binary, const uint64_t (&metric_thresholds)[4],
            const uint64_t max_msg_size);

        void maintain_known_connections(
            std::unordered_map<int, comm_session> &sessions, std::unordered_map<int, comm_client> &outbound_clients,
            const std::set<conf::ip_port_pair> &req_known_remotes, const SESSION_TYPE session_type, const bool is_binary,
            const uint64_t max_msg_size, const uint64_t (&metric_thresholds)[4]);

        std::string get_cgi_ip(const int fd);

    public:
        // Start accepting incoming connections
        int start(
            const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type, const bool is_binary, const bool use_size_header,
            const uint64_t (&metric_thresholds)[4], const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size);
        void stop();
        void firewall_ban(std::string_view ip, const bool unban);
    };

} // namespace comm

#endif
