#ifndef _HP_P2P_PEER_COMM_SESSION_
#define _HP_P2P_PEER_COMM_SESSION_

#include "../pchheader.hpp"
#include "../comm/comm_session.hpp"

namespace comm
{
    /** 
     * Represents a WebSocket connection to a Hot Pocket peer.
     */
    class peer_comm_session : public comm_session
    {
        using comm_session::comm_session; // Inherit constructors.

    private:
        int handle_connect();
        int handle_message(std::string_view msg);
        int handle_close();

    public:
        bool is_weakly_connected = false; // Holds whether this node is weakly connected to the other nodes.
    };

} // namespace comm

#endif
