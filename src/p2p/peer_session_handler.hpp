#ifndef _HP_P2P_PEER_SESSION_HANDLER_
#define _HP_P2P_PEER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "peer_comm_session.hpp"

namespace p2p
{
    int handle_peer_connect(comm::peer_comm_session &session);
    int handle_peer_message(comm::peer_comm_session &session, std::string_view message);
    int handle_self_message(std::string_view message);
    int handle_peer_close(const comm::comm_session &session);
    void handle_proposal_message(const p2pmsg::Container *container, const p2pmsg::Content *content);
    void handle_nonunl_proposal_message(const p2pmsg::Container *container, const p2pmsg::Content *content);
    void handle_npl_message(const p2pmsg::Container *container, const p2pmsg::Content *content);

} // namespace p2p
#endif