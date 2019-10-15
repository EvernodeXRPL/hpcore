#ifndef _SOCK_CLIENT_SESSION_H_
#define _SOCK_CLIENT_SESSION_H_

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "socket_session.hpp"
#include "socket_session_handler.hpp"

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
    tcp::resolver resolver_;                  // resolver used to resolve host and the port
    websocket::stream<beast::tcp_stream> ws_; // web socket stream used to send and receive messages
    std::string host_;                   // address of the server in which the client connects
    std::string port_;                   // port of the server in which client connects
    socket_session_handler &sess_handler_;    // handler passed to gain access to websocket events

    void on_resolve(error ec, tcp::resolver::results_type results);

    void on_connect(error ec, tcp::resolver::results_type::endpoint_type);

    void on_handshake(error ec);

    void on_close(error ec);

    void socket_client_fail(beast::error_code ec, char const *what);

    void on_write(error ec, std::size_t);

public:
    // Resolver and socket require an io_context
    socket_client(net::io_context &ioc, socket_session_handler &session_handler);

    //Entry point to the client which requires an active host and port
    void run(std::string_view host, std::string_view port);
};
} // namespace sock
#endif