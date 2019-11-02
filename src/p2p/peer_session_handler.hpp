#ifndef _HP_PEER_SESSION_HANDLER_
#define _HP_PEER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"
#include "../sock/socket_message.hpp"

namespace p2p
{

class peer_session_handler : public sock::socket_session_handler<peer_outbound_message>
{
public:
    void on_connect(sock::socket_session<peer_outbound_message> *session);

    void on_message(sock::socket_session<peer_outbound_message> *session, std::string_view message);

    void on_close(sock::socket_session<peer_outbound_message> *session);
};

} // namespace p2p
#endif