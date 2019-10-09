#ifndef _SOCK_CLIENT_SESSION_H_
#define _SOCK_CLIENT_SESSION_H_

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "socket_session.h"
#include "socket_session_handler.h"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{

/** 
 * Represents an active WebSocket client connection
 * Based on the implementation from https://github.com/vinniefalco/CppCon2018
*/
class socket_client : public std::enable_shared_from_this<socket_client>
{
    tcp::resolver resolver_;
    tcp::socket socket_;
    websocket::stream<beast::tcp_stream> ws_;
    std::string host_;
    unsigned short port_;
    socket_session_handler &sess_handler_;

    void on_resolve(error ec, tcp::resolver::results_type results);

    void on_connect(error ec, tcp::resolver::results_type::endpoint_type);

    void on_handshake(error ec);

    void on_close(error ec);

    void socket_client_fail(beast::error_code ec, char const *what);

public:
    // Resolver and socket require an io_context
    socket_client(net::io_context &ioc, socket_session_handler &session_handler);

    //Entry point to the client which requires an active host and port
    void run(char const *host, char const *port);
};
} // namespace sock
#endif