#include <iostream>
#include "socket_client.hpp"
#include "../hplog.hpp"

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace sock
{

socket_client::socket_client(net::io_context &ioc, socket_session_handler &session_handler)
    : resolver_(net::make_strand(ioc)), ws_(net::make_strand(ioc)), sess_handler_(session_handler)
{
}

/**
 * Entry point to socket client which will intiate a connection to server
*/
// boost async_resolve function requires a port as a string because of that port is passed as a string
void socket_client::run(std::string_view host, std::string_view port)
{
    host_ = host;
    port_ = port;

    // Look up the domain name
    resolver_.async_resolve(
        host,
        port,
        [self = shared_from_this()](error ec, tcp::resolver::results_type results) {
            self->on_resolve(ec, results);
        });
}

/**
 * Executes on completion of resolving the server
*/
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

/**
 * Executes on completion of connecting to the server
*/
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

/**
 * Executes on completion of handshake
*/
void socket_client::on_handshake(error ec)
{
    //Creates a new socket session object
    std::make_shared<socket_session>(
        ws_, sess_handler_)
        ->client_run(std::move(host_), std::move(port_), ec);
}

/**
 * Executes on error
*/
void socket_client::socket_client_fail(beast::error_code ec, char const *what)
{
    LOG_ERR << what << ": " << ec.message();
}

} // namespace sock
