#ifndef _HP_P2P_PEER_SESSION_HANDLER_
#define _HP_P2P_PEER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    int handle_peer_connect(p2p::peer_comm_session &session);
    int get_message_priority(std::string_view message);
    int handle_peer_message(p2p::peer_comm_session &session, std::string_view message);
    int handle_self_message(std::string_view message);
    int handle_peer_close(const p2p::peer_comm_session &session);
    void handle_peer_on_verified(p2p::peer_comm_session &session);

} // namespace p2p
#endif