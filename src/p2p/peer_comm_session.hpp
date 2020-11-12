#ifndef _HP_P2P_PEER_COMM_SESSION_
#define _HP_P2P_PEER_COMM_SESSION_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../comm/comm_session.hpp"

namespace p2p
{
    /** 
     * Represents a WebSocket connection to a Hot Pocket peer.
     */
    class peer_comm_session : public comm::comm_session
    {
        using comm_session::comm_session; // Inherit constructors.

    private:
        void handle_connect();
        int handle_message(std::string_view msg);
        void handle_close();

    public:
        std::optional<conf::ip_port_prop> known_ipport;  // A known ip/port information that matches with our peer list configuration.
        bool is_weakly_connected = false; // Holds whether this node is weakly connected to the other nodes.
        const std::string display_name();
    };

} // namespace comm

#endif
