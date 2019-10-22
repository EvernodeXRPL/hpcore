#ifndef _SOCK_SERVER_LISTENER_H_
#define _SOCK_SERVER_LISTENER_H_

#include <boost/asio.hpp>
#include "socket_session_handler.hpp"

namespace net = boost::asio; // namespace asio

using tcp = net::ip::tcp;
using error = boost::system::error_code; // from <boost/system/error_code.hpp>

namespace sock
{

/** 
 * Represents an active WebSocket server connection
 * Based on the implementation from https://github.com/vinniefalco/CppCon2018
*/
template <class T>
class socket_server : public std::enable_shared_from_this<socket_server<T>>
{
    tcp::acceptor acceptor_;               // acceptor which accepts new connections
    tcp::socket socket_;                   // socket in which the client connects
    socket_session_handler<T> &sess_handler_; // handler passed to gain access to websocket events

    void fail(error ec, char const *what);

    void on_accept(error ec);

public:
    socket_server(net::io_context &ioc, tcp::endpoint endpoint, socket_session_handler<T> &session_handler);

    // Start accepting incoming connections
    void run();
};
} // namespace sock

#endif