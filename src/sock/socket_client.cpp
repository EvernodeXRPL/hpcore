#include <iostream>
#include "socket_client.h"

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{

socket_client::socket_client(net::io_context &ioc, socket_session_handler &session_handler)
    : resolver_(net::make_strand(ioc)), ws_(net::make_strand(ioc)), sess_handler_(session_handler)
{
}

void socket_client::run(char const *host, char const *port)
{
    host_ = host;
    port_ = (unsigned short)std::strtoul(port, NULL, 0);
    
    // Look up the domain name
    resolver_.async_resolve(
        host,
        port,
        [self = shared_from_this()](error ec, tcp::resolver::results_type results) {
            self->on_resolve(ec, results);
        });
}

void socket_client::on_resolve(error ec, tcp::resolver::results_type results)
{
    if (ec)
        socket_client_fail(ec, "socket_client_resolve");

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(ws_).async_connect(
        results,
        [self = shared_from_this()](error ec, tcp::resolver::results_type::endpoint_type type) {
            self->on_connect(ec, type);
        });
}

void socket_client::on_connect(error ec, tcp::resolver::results_type::endpoint_type)
{
    if (ec)
        socket_client_fail(ec, "socket_client_connect");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    beast::get_lowest_layer(ws_).expires_never();

    // Set suggested timeout settings for the websocket
    ws_.set_option(
        websocket::stream_base::timeout::suggested(
            beast::role_type::client));

    // Perform the websocket handshake
    ws_.async_handshake(host_, "/",
                        [self = shared_from_this()](error ec) {
                            self->on_handshake(ec);
                        });
}

void socket_client::on_handshake(error ec)
{
    std::make_shared<socket_session>(
        ws_, sess_handler_)
        ->client_run(port_, host_, ec);
}

void socket_client::socket_client_fail(beast::error_code ec, char const *what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

} // namespace sock
