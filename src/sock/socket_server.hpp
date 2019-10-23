#ifndef _SOCK_SERVER_LISTENER_H_
#define _SOCK_SERVER_LISTENER_H_

#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include "socket_session_handler.hpp"
#include "../hplog.hpp"

namespace net = boost::asio; // namespace asio

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace sock
{

/** 
 * Represents an active WebSocket server connection
 * Based on the implementation from https://github.com/vinniefalco/CppCon2018
*/
template <class T>
class socket_server : public std::enable_shared_from_this<socket_server<T>>
{
    tcp::acceptor acceptor_;               // acceptor which accepts new connections
    tcp::socket socket_;                   // socket in which the client connects
    socket_session_handler<T> &sess_handler_; // handler passed to gain access to websocket events

    void fail(error_code ec, char const *what);

    void on_accept(error_code ec);

public:
    socket_server(net::io_context &ioc, tcp::endpoint endpoint, socket_session_handler<T> &session_handler);

    // Start accepting incoming connections
    void run();
};


template <class T>
socket_server<T>::socket_server(net::io_context &ioc, tcp::endpoint endpoint, socket_session_handler<T> &session_handler)
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
template <class T>
void socket_server<T>::run()
{

    // Start accepting a connection
    acceptor_.async_accept(
        socket_,
        [self = this->shared_from_this()](error_code ec) {
            self->on_accept(ec);
        });
}

/**
 * Executes on error
*/
template <class T>
void socket_server<T>::fail(error_code ec, char const *what)
{
    // Don't report on canceled operations
    if (ec == net::error::operation_aborted)
        return;
    LOG_ERR << what << ": " << ec.message();
}

/**
 * Executes on acceptance of new connection
*/
template <class T>
void socket_server<T>::on_accept(error_code ec)
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
        std::make_shared<socket_session<T>>(
            ws, sess_handler_)
            ->server_run(std::move(address), std::move(port));
    }

    // Accept another connection
    acceptor_.async_accept(
        socket_,
        [self = this->shared_from_this()](error_code ec) {
            self->on_accept(ec);
        });
}

} // namespace sock

#endif