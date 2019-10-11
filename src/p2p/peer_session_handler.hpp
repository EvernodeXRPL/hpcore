#ifndef _HP_P2P_SESSION_H_
#define _HP_P2P_SESSION_H_

#include <boost/beast/core.hpp>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

using error = boost::system::error_code;

namespace p2p
{
class peer_session_handler : public sock::socket_session_handler
{
public:
    void on_connect(sock::socket_session *session, error ec);
    void on_message(sock::socket_session *session, std::shared_ptr<std::string const> const &message, error ec);
    void on_close(sock::socket_session *session);
};

void open_listen();
} // namespace p2p
#endif