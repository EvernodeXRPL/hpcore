#ifndef _HP_P2P_PEER_COMM_SERVER_
#define _HP_P2P_PEER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    class peer_comm_server : public comm::comm_server<peer_comm_session>
    {
    private:
        const std::set<conf::ip_port_pair> &req_known_remotes;
        std::thread known_peers_thread; // Known peers connection establishment thread.
        void maintain_known_connections();

    protected:
        void start_custom_jobs();
        void stop_custom_jobs();
        int process_custom_messages();

    public:
        peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[4],
                         const uint64_t max_msg_size, const std::set<conf::ip_port_pair> &req_known_remotes);
    };
} // namespace p2p

#endif