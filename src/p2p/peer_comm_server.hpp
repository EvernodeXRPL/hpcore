#ifndef _HP_P2P_PEER_COMM_SERVER_
#define _HP_P2P_PEER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    class peer_comm_server : public comm::comm_server<peer_comm_session>
    {
    private:
        int custom_connection_invocations = -1;
        // std::thread known_peers_thread; // Known peers connection establishment thread.
        std::thread req_peers_thread;    // Peer list requesting thread.
        std::thread peer_request_thread; // Thread to request known peer list from a random peer.
        void maintain_known_connections();
        void peer_list_request_loop();

    protected:
        void start_custom_jobs();
        void stop_custom_jobs();
        int process_custom_messages();
        void custom_connections();

    public:
        std::mutex req_known_remotes_mutex;
        std::list<conf::peer_properties> &req_known_remotes;
        peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[4],
                         const uint64_t max_msg_size, std::list<conf::peer_properties> &req_known_remotes);
    };
} // namespace p2p

#endif