#ifndef _SOCK_SERVER_LISTENER_H_
#define _SOCK_SERVER_LISTENER_H_

#include <boost/asio.hpp>
#include "socket_session_handler.h"

namespace net = boost::asio; // namespace asio

using tcp = net::ip::tcp;
using error = boost::system::error_code; // from <boost/system/error_code.hpp>

namespace sock
{

/** Represents an active WebSocket server connection
*/
class socket_server : public std::enable_shared_from_this<socket_server>
{
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    socket_session_handler &sess_handler_;

    void fail(error ec, char const *what);
    void on_accept(error ec);

public:
    socket_server(
        net::io_context &ioc,
        tcp::endpoint endpoint,
        socket_session_handler &session_handler
        );

    // Start accepting incoming connections
    void run();
};
} // namespace sock

#endif