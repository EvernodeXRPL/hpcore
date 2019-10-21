
#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>
#include "socket_server.hpp"
#include "../hplog.hpp"

namespace net = boost::asio; // namespace asio

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace sock
{

socket_server::socket_server(net::io_context &ioc, tcp::endpoint endpoint, socket_session_handler &session_handler)
    : acceptor_(ioc), socket_(ioc),sess_handler_(session_handler)
{
    error_code ec;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec)
    {
        fail(ec, "open");
        return;
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true));
    if (ec)
    {
        fail(ec, "set_option");
        return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec)
    {
        fail(ec, "bind");
        return;
    }

    // Start listening for connections
    acceptor_.listen(
        net::socket_base::max_listen_connections, ec);
    if (ec)
    {
        fail(ec, "listen");
        return;
    }
}

/**
 * Entry point to socket server which accepts new connections
*/
void socket_server::run()
{

    // Start accepting a connection
    acceptor_.async_accept(
        socket_,
        [self = shared_from_this()](error_code ec) {
            self->on_accept(ec);
        });
}

/**
 * Executes on error
*/
void socket_server::fail(error_code ec, char const *what)
{
    // Don't report on canceled operations
    if (ec == net::error::operation_aborted)
        return;
    LOG_ERR << what << ": " << ec.message();
}

/**
 * Executes on acceptance of new connection
*/
void socket_server::on_accept(error_code ec)
{
    if (ec)
    {
        return fail(ec, "accept");
    }
    else
    {
        std::string port = std::to_string(socket_.remote_endpoint().port());
        std::string address = socket_.remote_endpoint().address().to_string();

        //Creating websocket stream required to pass to initiate a new session
        websocket::stream<beast::tcp_stream> ws(std::move(socket_));

       // Launch a new session for this connection
        std::make_shared<socket_session>(
            ws, sess_handler_)
            ->server_run(std::move(address), std::move(port));
    }

    // Accept another connection
    acceptor_.async_accept(
        socket_,
        [self = shared_from_this()](error_code ec) {
            self->on_accept(ec);
        });
}
} // namespace sock