#include "../pchheader.hpp"
#include "socket_message.hpp"
#include "socket_session.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
using error_code = boost::system::error_code;

namespace sock
{

// The following functions exist to separate out beast web sockets lambda expressions from other code.
// This reduces lambda expression compilation time in regular code changes as long as this file is not touched.

template <class T>
void socket_session<T>::ws_next_layer_async_handshake(const ssl::stream_base::handshake_type handshake_type)
{
    try
    {
        // Perform the SSL handshake
        ws.next_layer().async_handshake(
            handshake_type,
            [sp = this->shared_from_this()](error_code ec) {
                sp->on_ssl_handshake(ec);
            });
    }
    catch (...)
    {
        this->handle_exception("ssl_handshake");
    }
}

template <class T>
void socket_session<T>::ws_async_accept()
{
    try
    {
        ws.async_accept(
            [sp = this->shared_from_this()](
                error_code ec) {
                sp->on_accept(ec);
            });
    }
    catch (...)
    {
        this->handle_exception("accept");
    }
}

template <class T>
void socket_session<T>::ws_async_handshake()
{
    try
    {
        ws.async_handshake(this->address, "/",
                           [sp = this->shared_from_this()](
                               error_code ec) {
                               sp->on_accept(ec);
                           });
    }
    catch (...)
    {
        this->handle_exception("handshake");
    }
}

template <class T>
void socket_session<T>::ws_async_read()
{
    try
    {
        ws.async_read(
            buffer,
            [sp = this->shared_from_this()](
                error_code ec, std::size_t bytes) {
                sp->on_read(ec, bytes);
            });
    }
    catch (...)
    {
        this->handle_exception("read");
    }
}

template <class T>
void socket_session<T>::ws_async_write(std::string_view message)
{
    try
    {
        ws.async_write(
            // Project the outbound_message buffer from the queue front into the asio buffer.
            net::buffer(message.data(), message.length()),
            [sp = this->shared_from_this()](
                error_code ec, std::size_t bytes) {
                sp->on_write(ec, bytes);
            });
    }
    catch (...)
    {
        this->handle_exception("write");
    }
}

template <class T>
void socket_session<T>::ws_async_close()
{
    try
    {
        ws.async_close(websocket::close_code::normal,
                       [sp = this->shared_from_this()](
                           error_code ec) {
                           sp->on_close(ec, 0);
                       });
    }
    catch (...)
    {
        this->handle_exception("close");
    }
}

// Template instantiations.
template class socket_session<p2p::peer_outbound_message>;
template class socket_session<usr::user_outbound_message>;

} // namespace sock