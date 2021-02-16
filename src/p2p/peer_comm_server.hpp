#ifndef _HP_P2P_PEER_COMM_SERVER_
#define _HP_P2P_PEER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    // Globally exposed weakly connected status variable.
    extern bool is_weakly_connected;

    class peer_comm_server : public comm::comm_server<peer_comm_session>
    {
    private:
        int custom_connection_invocations = -1;
        // std::thread known_peers_thread; // Known peers connection establishment thread.
        std::thread peer_managing_thread; // Thread to request known peer list from a random peer and announce available capacity.
        uint16_t connected_status_check_counter = 0;

        void maintain_known_connections();
        void peer_managing_loop();
        void detect_if_weakly_connected();

    protected:
        void start_custom_jobs();
        void stop_custom_jobs();
        int process_custom_messages();
        void custom_connections();

    public:
        std::atomic<uint16_t> known_remote_count = 0;
        std::mutex req_known_remotes_mutex;
        std::vector<conf::peer_properties> req_known_remotes;
        peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[5], const uint64_t max_msg_size,
                         const uint64_t max_in_connections, const uint64_t max_in_connections_per_host,
                         const std::vector<conf::peer_properties> &req_known_remotes);
    };
} // namespace p2p

#endif