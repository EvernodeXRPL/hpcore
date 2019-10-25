#include "socket_client.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../usr/user_session_handler.hpp"

namespace sock
{

template <class T>
socket_client<T>::socket_client(net::io_context &ioc, ssl::context &ctx, socket_session_handler<T> &session_handler, const session_options &session_options)
    : resolver(net::make_strand(ioc)), ws(net::make_strand(ioc), ctx), sess_handler(session_handler), sess_opts(session_options)
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
    {
        socket_client_fail(ec, "socket_client_connect");
    }
    else
    {
        //Creates a new socket session object
        std::make_shared<socket_session<T>>(
            std::move(ws), sess_handler)
            ->run(std::move(host), std::move(port), false, sess_opts);
    }
}

/**
 * Executes on error
*/
template <class T>
void socket_client<T>::socket_client_fail(beast::error_code ec, char const *what)
{
    LOG_ERR << what << ": " << ec.message();
}

/**
 * Declaring templates with possible values for T because keeping all those in hpp file makes compile take a long time
 */ 
template socket_client<p2p::peer_outbound_message>::socket_client(net::io_context &ioc, ssl::context &ctx, socket_session_handler<p2p::peer_outbound_message> &session_handler, const session_options &session_options);
template void socket_client<p2p::peer_outbound_message>::run(std::string_view host, std::string_view port);

template socket_client<usr::user_outbound_message>::socket_client(net::io_context &ioc, ssl::context &ctx, socket_session_handler<usr::user_outbound_message> &session_handler, const session_options &session_options);
template void socket_client<usr::user_outbound_message>::run(std::string_view host, std::string_view port);
} // namespace sock
