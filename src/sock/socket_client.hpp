#ifndef _SOCK_CLIENT_SESSION_H_
#define _SOCK_CLIENT_SESSION_H_

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "socket_session.hpp"
#include "socket_session_handler.hpp"
#include "../hplog.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

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
    tcp::resolver resolver;                   // resolver used to resolve host and the port
    websocket::stream<beast::tcp_stream> ws;  // web socket stream used to send and receive messages
    std::string host;                         // address of the server in which the client connects
    std::string port;                         // port of the server in which client connects
    socket_session_handler<T> &sess_handler_; // handler passed to gain access to websocket events
    session_options &sess_opts;              // store session specific options

    void on_resolve(error ec, tcp::resolver::results_type results);

    void on_connect(error ec, tcp::resolver::results_type::endpoint_type);

    void on_handshake(error ec);

    void on_close(error ec);

    void socket_client_fail(beast::error_code ec, char const *what);

    void on_write(error ec, std::size_t);

public:
    // Resolver and socket require an io_context
    socket_client(net::io_context &ioc, socket_session_handler<T> &session_handler, session_options &sess_opts);

    //Entry point to the client which requires an active host and port
    void run(std::string_view host, std::string_view port);
};

template <class T>
socket_client<T>::socket_client(net::io_context &ioc, socket_session_handler<T> &session_handler, session_options &sess_opts)
    : resolver(net::make_strand(ioc)), ws(net::make_strand(ioc)), sess_handler_(session_handler), sess_opts(sess_opts)
{
}

/**
 * Entry point to socket client which will intiate a connection to server
*/
// boost async_resolve function requires a port as a string because of that port is passed as a string
template <class T>
void socket_client<T>::run(std::string_view host, std::string_view port)
{
    this->host = host;
    this->port = port;

    // Look up the domain name
    resolver.async_resolve(
        host,
        port,
        [self = this->shared_from_this()](error ec, tcp::resolver::results_type results) {
            self->on_resolve(ec, results);
        });
}

/**
 * Executes on completion of resolving the server
*/
template <class T>
void socket_client<T>::on_resolve(error ec, tcp::resolver::results_type results)
{
    if (ec)
        socket_client_fail(ec, "socket_client_resolve");

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(ws).async_connect(
        results,
        [self = this->shared_from_this()](error ec, tcp::resolver::results_type::endpoint_type type) {
            self->on_connect(ec, type);
        });
}

/**
 * Executes on completion of connecting to the server
*/
template <class T>
void socket_client<T>::on_connect(error ec, tcp::resolver::results_type::endpoint_type)
{
    if (ec)
        socket_client_fail(ec, "socket_client_connect");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    beast::get_lowest_layer(ws).expires_never();

    // Set suggested timeout settings for the websocket
    ws.set_option(
        websocket::stream_base::timeout::suggested(
            beast::role_type::client));

    // Perform the websocket handshake
    ws.async_handshake(host, "/",
                        [self = this->shared_from_this()](error ec) {
                            self->on_handshake(ec);
                        });
}

/**
 * Executes on completion of handshake
*/
template <class T>
void socket_client<T>::on_handshake(error ec)
{
    //Creates a new socket session object
    std::make_shared<socket_session<T>>(
        ws, sess_handler_)
        ->client_run(std::move(host), std::move(port), ec);
}

/**
 * Executes on error
*/
template <class T>
void socket_client<T>::socket_client_fail(beast::error_code ec, char const *what)
{
    LOG_ERR << what << ": " << ec.message();
}

} // namespace sock
#endif