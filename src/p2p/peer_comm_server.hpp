#ifndef _HP_P2P_PEER_COMM_SERVER_
#define _HP_P2P_PEER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    class peer_comm_server : public comm::comm_server<peer_comm_session>
    {
        using comm::comm_server<peer_comm_session>::comm_server; // Inherit constructors.
    };
} // namespace usr

#endif