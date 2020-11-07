#ifndef _HP_PEER_SESSION_HANDLER_
#define _HP_PEER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    int handle_peer_connect(comm::peer_comm_session &session);
    int handle_peer_message(comm::peer_comm_session &session, std::string_view message);
    int handle_self_message(std::string_view message);
    int handle_peer_close(const comm::hpws_comm_session &session);

} // namespace p2p
#endif