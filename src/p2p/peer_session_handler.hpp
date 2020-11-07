#ifndef _HP_PEER_SESSION_HANDLER_
#define _HP_PEER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "../comm/comm_session_handler.hpp"
#include "../comm/comm_session.hpp"
#include "../comm/hpws_comm_session.hpp"

namespace p2p
{

class peer_session_handler : public comm::comm_session_handler
{
public:
    int on_connect(comm::hpws_comm_session &session) const;
    int on_message(comm::comm_session &session, std::string_view message) const;
    void on_close(const comm::hpws_comm_session &session) const;
};

} // namespace p2p
#endif