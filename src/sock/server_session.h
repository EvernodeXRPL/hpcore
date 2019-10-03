#ifndef _SOCK_SERVER_SESSION_H_
#define _SOCK_SERVER_SESSION_H_

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace beast = boost::beast;
namespace net = boost::asio; 
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

// Forward declaration
class shared_state;

/** Represents an active WebSocket connection to the server
*/
class server_session : public std::enable_shared_from_this<server_session>
{
    beast::flat_buffer buffer_;
    websocket::stream<tcp::socket> ws_;
    std::shared_ptr<shared_state> state_;
    std::vector<std::shared_ptr<std::string const>> queue_;

    void fail(error ec, char const* what);
    void on_accept(error ec);
    void on_read(error ec, std::size_t bytes_transferred);
    void on_write(error ec, std::size_t bytes_transferred);

public:
    server_session(
        tcp::socket socket,
        std::shared_ptr<shared_state> const& state);

    ~server_session();

    void run();

    // Send a message
    void
    send(std::shared_ptr<std::string const> const& ss);
};
#endif
