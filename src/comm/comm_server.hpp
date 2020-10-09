#ifndef _HP_COMM_SERVER_
#define _HP_COMM_SERVER_

#include "../pchheader.hpp"
#include "comm_session.hpp"
#include "../hpws/hpws.hpp"

namespace comm
{

    class comm_server
    {
        std::optional<hpws::server> hpws_server;
        std::thread watchdog_thread;                  // Connection watcher thread.
        std::thread inbound_message_processor_thread; // Incoming message processor thread.
        bool should_stop_listening = false;

        std::list<comm_session> sessions;
        std::mutex sessions_mutex;

        void connection_watchdog(
            const SESSION_TYPE session_type, const uint64_t (&metric_thresholds)[4],
            const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size);

        void inbound_message_processor_loop(const SESSION_TYPE session_type);

        int start_hpws_server(const uint16_t port, const bool require_tls, const uint64_t max_msg_size);

        int poll_fds(pollfd *pollfds, const int accept_fd, const std::list<comm_session> &sessions);

        void check_for_new_connection(
            std::list<comm_session> &sessions, const SESSION_TYPE session_type, const uint64_t (&metric_thresholds)[4]);

        void maintain_known_connections(
            std::list<comm_session> &sessions, const std::set<conf::ip_port_pair> &req_known_remotes,
            const SESSION_TYPE session_type, const uint64_t max_msg_size, const uint64_t (&metric_thresholds)[4]);

        std::string get_cgi_ip(const int fd);

    public:
        // Start accepting incoming connections
        int start(
            const uint16_t port, const SESSION_TYPE session_type, const bool require_tls,
            const uint64_t (&metric_thresholds)[4], const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size);
        void stop();
        void firewall_ban(std::string_view ip, const bool unban);
    };

} // namespace comm

#endif
