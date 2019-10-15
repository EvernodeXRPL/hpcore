#ifndef _SOCK_SERVER_SESSION_H_
#define _SOCK_SERVER_SESSION_H_

#include <string>
#include <vector>
#include <bitset>
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
    beast::flat_buffer buffer_;               // used to store incoming messages
    websocket::stream<beast::tcp_stream> ws_; // websocket stream used send an recieve messages
    std::vector<std::string> queue_;          // uses to store messages temporarily until it is sent to the relevant party
    socket_session_handler &sess_handler_;    // handler passed to gain access to websocket events

    void fail(error ec, char const *what);

    void on_accept(error ec);

    void on_read(error ec, std::size_t bytes_transferred);

    void on_write(error ec, std::size_t bytes_transferred);

    void on_close(error ec, std::int8_t type);

public:
    socket_session(websocket::stream<beast::tcp_stream> &websocket, socket_session_handler &sess_handler);

    // Port and the address of the remote party is being saved to used in the session handler
    // to identify from which remote party the message recieved. Since the port is passed as a string 
    // from the parent we store as it is, since we are not going to pass it anywhere or used in a method

    // The port of the remote party.
    std::string port_;

    // The IP address of the remote party.
    std::string address_;

    // The unique identifier of the remote party (format <ip>:<port>).
    std::string uniqueid_;

    // The set of util::SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags_;

    void server_run(const std::string &&address, const std::string &&port);
    void client_run(const std::string &&address, const std::string &&port, error ec);

    void send(std::string &&ss);

    // When called, initializes the unique id string for this session.
    void init_uniqueid();

    void close();
};
} // namespace sock
#endif
