#ifndef _SOCK_CLIENT_SESSION_H_
#define _SOCK_CLIENT_SESSION_H_

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "socket_session.h"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{

class socket_client : public std::enable_shared_from_this<socket_client>
{
    tcp::resolver resolver_;
    tcp::socket socket_;
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    std::string host_;
    std::shared_ptr<socket_session> const& sess_;
    

    void on_resolve(error ec, tcp::resolver::results_type results);
    void on_connect(error ec, tcp::resolver::results_type::endpoint_type);
    void on_handshake(error ec);
    void on_close(error ec);
    void socket_client_fail(beast::error_code ec, char const *what);

public:
    // Resolver and socket require an io_context
    socket_client(net::io_context &ioc, std::shared_ptr<socket_session> const& session);

    ~socket_client();

    void
    run(char const *host, char const *port);
};
} // namespace sock
#endif