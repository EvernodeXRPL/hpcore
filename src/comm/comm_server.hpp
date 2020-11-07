#ifndef _HP_COMM_COMM_SERVER_
#define _HP_COMM_COMM_SERVER_

#include "../pchheader.hpp"
#include "../hpws/hpws.hpp"

namespace comm
{
    template <typename T>
    class comm_server
    {
    protected:
        const std::string name;
        const uint16_t port;
        const uint64_t (&metric_thresholds)[4];
        const uint64_t max_msg_size;
        std::optional<hpws::server> hpws_server;
        std::thread watchdog_thread;                  // Connection watcher thread.
        std::thread inbound_message_processor_thread; // Incoming message processor thread.
        bool should_stop_listening = false;

        std::list<T> sessions;
        std::mutex sessions_mutex;

        void connection_watchdog();
        void check_for_new_connection();
        void inbound_message_processor_loop();
        int start_hpws_server();
        int poll_fds(pollfd *pollfds, const int accept_fd, const std::list<T> &sessions);

    public:
        comm_server(std::string_view name, const uint16_t port, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size);
        int start();
        void stop();
    };

} // namespace comm

#endif
