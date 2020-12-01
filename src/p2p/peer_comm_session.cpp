#include "../pchheader.hpp"
#include "peer_comm_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    int peer_comm_session::handle_connect()
    {
        return p2p::handle_peer_connect(*this);
    }

    int peer_comm_session::handle_message(std::string_view msg)
    {
        return p2p::handle_peer_message(*this, msg);
    }

    void peer_comm_session::handle_close()
    {
        p2p::handle_peer_close(*this);
    }

    void peer_comm_session::handle_on_verified()
    {
        p2p::handle_peer_on_verified(*this);
    }

} // namespace p2p