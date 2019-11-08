#include "socket_server.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../usr/user_session_handler.hpp"

namespace sock
{

template <class T>
socket_server<T>::socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<T> &session_handler, const session_options &session_options)
    : acceptor(net::make_strand(ioc)), ioc(ioc), ctx(ctx), sess_handler(session_handler), sess_opts(session_options)
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
    // Adding ssl context options disallowing requests which supports sslv2 and sslv3 which have security vulnerabilitis
    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::no_sslv3);

    //Providing the certification file for ssl context
    ctx.use_certificate_chain_file(conf::ctx.tlsCertFile);

    // Providing key file for the ssl context
    ctx.use_private_key_file(
        conf::ctx.tlsKeyFile,
        boost::asio::ssl::context::pem);

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
        const std::string port = std::to_string(socket.remote_endpoint().port());
        const std::string address = socket.remote_endpoint().address().to_string();

        //Creating websocket stream required to pass to initiate a new session
        websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws(std::move(socket), ctx);

        // Launch a new session for this connection
        std::make_shared<socket_session<T>>(std::move(ws), sess_handler)
            ->run(std::move(address), std::move(port), true, sess_opts);
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

/**
 * Declaring templates with possible values for T because keeping all those in hpp file makes compile take a long time
 */ 
template socket_server<p2p::peer_outbound_message>::socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<p2p::peer_outbound_message> &session_handler, const session_options &session_options);
template void socket_server<p2p::peer_outbound_message>::run();

template socket_server<usr::user_outbound_message>::socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<usr::user_outbound_message> &session_handler, const session_options &session_options);
template void socket_server<usr::user_outbound_message>::run();

} // namespace sock