#ifndef _SOCK_SERVER_LISTENER_H_
#define _SOCK_SERVER_LISTENER_H_

#include "socket_session_handler.hpp"
#include "../hplog.hpp"

namespace net = boost::asio;      // namespace asio
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

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
    tcp::acceptor acceptor; // acceptor which accepts new connections
    net::io_context &ioc;   // socket in which the client connects
    ssl::context &ctx;      // ssl context which provides support for tls
    socket_session_handler<T> &sess_handler; // handler passed to gain access to websocket events

    void fail(error_code ec, char const *what);

    void on_accept(error_code ec, tcp::socket socket);

public:
    socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<T> &session_handler);

    // Start accepting incoming connections
    void run();
};

template <class T>
socket_server<T>::socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<T> &session_handler)
    : acceptor(net::make_strand(ioc)), ioc(ioc), ctx(ctx), sess_handler(session_handler)
{
    error_code ec;

    // Open the acceptor
    acceptor.open(endpoint.protocol(), ec);
    if (ec)
    {
        fail(ec, "open");
        return;
    }

    // Allow address reuse
    acceptor.set_option(net::socket_base::reuse_address(true));
    if (ec)
    {
        fail(ec, "set_option");
        return;
    }

    // Bind to the server address
    acceptor.bind(endpoint, ec);
    if (ec)
    {
        fail(ec, "bind");
        return;
    }

    // Start listening for connections
    acceptor.listen(
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
    acceptor.async_accept(
        net::make_strand(ioc),
        beast::bind_front_handler(
            &socket_server<T>::on_accept,
            this->shared_from_this()));
}

/**
 * Executes on acceptance of new connection
*/
template <class T>
void socket_server<T>::on_accept(error_code ec, tcp::socket socket)
{
    if (ec)
    {
        return fail(ec, "accept");
    }
    else
    {

        std::string port = std::to_string(socket.remote_endpoint().port());
        std::string address = socket.remote_endpoint().address().to_string();

        //Creating websocket stream required to pass to initiate a new session
        websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws(std::move(socket), ctx);

        // Launch a new session for this connection
        std::make_shared<socket_session<T>>(
            std::move(ws), sess_handler)
            ->run(std::move(address), std::move(port), true);
    }

    // Accept another connection
    acceptor.async_accept(
        net::make_strand(ioc),
        beast::bind_front_handler(
            &socket_server<T>::on_accept,
            this->shared_from_this()));
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

} // namespace sock

#endif