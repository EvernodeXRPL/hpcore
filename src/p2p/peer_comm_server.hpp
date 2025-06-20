#ifndef _HP_P2P_PEER_COMM_SERVER_
#define _HP_P2P_PEER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "../util/ttl_set.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    struct peer_properties;

    class peer_comm_server : public comm::comm_server<peer_comm_session>
    {
    private:
        int custom_connection_invocations = -1;
        std::thread peer_managing_thread; // Thread to manage peer connections.
        uint16_t connected_status_check_counter = 0;

        void maintain_known_connections();
        void peer_managing_loop();
        void detect_if_weakly_connected();

    protected:
        void start_custom_jobs();
        void stop_custom_jobs();
        int process_custom_messages();

    public:
        std::atomic<uint16_t> known_remote_count = 0;
        std::mutex req_known_remotes_mutex;
        std::vector<peer_properties> req_known_remotes;
        util::ttl_set dead_known_peers;
        peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[5], const uint64_t max_msg_size,
                         const uint64_t max_in_connections, const uint64_t max_in_connections_per_host,
                         const std::vector<peer_properties> &req_known_remotes);
    };
} // namespace p2p

#endif