#ifndef _SOCK_SERVER_SESSION_H_
#define _SOCK_SERVER_SESSION_H_

#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "socket_session_handler.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{

//Forward Declaration
class socket_session_handler;

/** 
 * Represents an active WebSocket connection
*/
class socket_session : public std::enable_shared_from_this<socket_session>
{
    beast::flat_buffer buffer_;
    websocket::stream<beast::tcp_stream> ws_;
    std::vector<std::shared_ptr<std::string const>> queue_;
    socket_session_handler &sess_handler_;

    void fail(error ec, char const *what);

    void on_accept(error ec);

    void on_read(error ec, std::size_t bytes_transferred);

    void on_write(error ec, std::size_t bytes_transferred);

    void on_close(error ec, std::int8_t type);

public:
    socket_session(websocket::stream<beast::tcp_stream> &websocket, socket_session_handler &sess_handler);

    // The port of the remote party.
    std::uint16_t port_;
    // The IP address of the remote party.
    std::string address_;
    // The unique identifier of the remote party (format <ip>:<port>).
    std::string uniqueid_;

    void server_run(const std::uint16_t port, const std::string &address);
    void client_run(const std::uint16_t port, const std::string &address, error ec);

    //Used to send message through an active websocket connection
    void send(std::shared_ptr<std::string const> const &ss);

    void close();
};
} // namespace sock
#endif
