#ifndef _HP_P2P_PEER_COMM_SESSION_
#define _HP_P2P_PEER_COMM_SESSION_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../comm/comm_session.hpp"

namespace p2p
{
    /**
     * Represents a WebSocket connection to a HotPocket peer.
     */
    class peer_comm_session : public comm::comm_session
    {
        using comm_session::comm_session; // Inherit constructors.

    private:
        int handle_connect();
        int get_message_priority(std::string_view msg);
        int handle_message(std::string_view msg);
        void handle_close();
        void handle_on_verified();

    public:
        std::optional<conf::peer_ip_port> known_ipport; // A known ip/port information that matches with our peer list configuration.
        bool need_consensus_msg_forwarding = false;     // Holds whether this node requires consensus message forwarding.
        bool is_unl = false;                            // Whether this session's pubkey is in unl list.
        uint32_t reported_time_config = 0;              // Initial time config reported by this peer on peer challenge.
        bool is_full_history;                           // Stores whether the connection is to a full history node or not.
    };

} // namespace p2p

#endif
