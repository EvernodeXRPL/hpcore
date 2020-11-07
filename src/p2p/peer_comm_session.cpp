#include "../pchheader.hpp"
#include "peer_comm_session.hpp"
#include "peer_session_handler.hpp"

namespace comm
{
    int peer_comm_session::handle_connect()
    {
        return p2p::handle_peer_connect(*this);
    }

    int peer_comm_session::handle_message(std::string_view msg)
    {
        return p2p::handle_peer_message(*this, msg);
    }

    int peer_comm_session::handle_close()
    {
        return p2p::handle_peer_close(*this);
    }

} // namespace comm