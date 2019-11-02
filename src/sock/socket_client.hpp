#ifndef _HP_SOCKET_CLIENT_
#define _HP_SOCKET_CLIENT_

#include "socket_session_handler.hpp"
#include "../hplog.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace ssl = boost::asio::ssl; 

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{
/** 
 * Represents an active WebSocket client connection
 * Based on the implementation from https://github.com/vinniefalco/CppCon2018
*/
template <class T>
class socket_client : public std::enable_shared_from_this<socket_client<T>>
{
    tcp::resolver resolver;                                     // resolver used to resolve host and the port
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws; // web socket stream used to send and receive messages
    std::string host;                                           // address of the server in which the client connects
    std::string port;                                           // port of the server in which client connects
    socket_session_handler<T> &sess_handler;                    // handler passed to gain access to websocket events
    const session_options &sess_opts;                                 // session options needed to pass to session

    void on_resolve(error ec, tcp::resolver::results_type results);

    void on_connect(error ec, tcp::resolver::results_type::endpoint_type);

    void on_close(error ec);

    void socket_client_fail(beast::error_code ec, char const *what);

    void on_write(error ec, std::size_t);

public:
    // Resolver and socket require an io_context
    socket_client(net::io_context &ioc, ssl::context &ctx, socket_session_handler<T> &session_handler, const session_options &session_options);

    //Entry point to the client which requires an active host and port
    void run(std::string_view host, std::string_view port);
};
} // namespace sock
#endif