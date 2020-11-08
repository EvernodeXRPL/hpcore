#include "../pchheader.hpp"
#include "peer_comm_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    void peer_comm_session::handle_connect()
    {
        p2p::handle_peer_connect(*this);
    }

    int peer_comm_session::handle_message(std::string_view msg)
    {
        return p2p::handle_peer_message(*this, msg);
    }

    void peer_comm_session::handle_close()
    {
        p2p::handle_peer_close(*this);
    }

    /**
     * Returns printable name for the session based on uniqueid (used for logging).
     */
    const std::string peer_comm_session::display_name()
    {
        if (challenge_status == comm::CHALLENGE_STATUS::CHALLENGE_VERIFIED)
        {
            // Peer sessions use pubkey hex as unique id (skipping first 2 bytes key type prefix).
            return uniqueid.substr(2, 10) + (is_inbound ? ":in" : ":out");
        }

        return comm_session::display_name();
    }

} // namespace p2p