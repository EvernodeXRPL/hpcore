#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include "socket_session.hpp"

namespace net = boost::asio;

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace sock
{

socket_session::socket_session(websocket::stream<beast::tcp_stream> &websocket, socket_session_handler &sess_handler)
    : ws_(std::move(websocket)), sess_handler_(sess_handler)
{
}

void socket_session::server_run(const unsigned short &port, const std::string &address)
{
    port_ = port;
    address_ = address;

    // Create a unique id for the session combining ip and port.
    uniqueid_ = address + ":";
    uniqueid_.append(std::to_string(port));

    // Accept the websocket handshake
    ws_.async_accept(
        [sp = shared_from_this()](
            error ec) {
            sp->on_accept(ec);
        });
}

void socket_session::client_run(const unsigned short &port, const std::string &address, error ec)
{
    port_ = port;
    address_ = address;

    // Create a unique id for the session combining ip and port.
    uniqueid_ = address + ":";
    uniqueid_.append(std::to_string(port));

    sess_handler_.on_connect(this, ec);
    if (ec)
        return fail(ec, "handshake");

    ws_.async_read(
        buffer_,
        [sp = shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

void socket_session::fail(error_code ec, char const *what)
{
    // Don't report these
    if (ec == net::error::operation_aborted ||
        ec == websocket::error::closed)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

void socket_session::on_accept(error_code ec)
{
    sess_handler_.on_connect(this, ec);

    // Handle the error, if any
    if (ec)
        return fail(ec, "accept");

    // Read a message
    ws_.async_read(
        buffer_,
        [sp = shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

void socket_session::on_read(error_code ec, std::size_t)
{
    auto const string_message = std::make_shared<std::string const>(std::move(beast::buffers_to_string(buffer_.data())));
    sess_handler_.on_message(this, string_message, ec);

    // Handle the error, if any
    if (ec)
        return fail(ec, "read");

    // Clear the buffer
    buffer_.consume(buffer_.size());

    // Read another message
    ws_.async_read(
        buffer_,
        [sp = shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

void socket_session::send(std::shared_ptr<std::string const> const &ss)
{
    // Always add to queue
    queue_.push_back(ss);

    // Are we already writing?
    if (queue_.size() > 1)
        return;

    // We are not currently writing, so send this immediately
    ws_.async_write(
        net::buffer(*queue_.front()),
        [sp = shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_write(ec, bytes);
        });
}

void socket_session::on_write(error_code ec, std::size_t)
{
    // Handle the error, if any
    if (ec)
        return fail(ec, "write");

    // Remove the string from the queue
    queue_.erase(queue_.begin());

    // Send the next message if any
    if (!queue_.empty())
        ws_.async_write(
            net::buffer(*queue_.front()),
            [sp = shared_from_this()](
                error_code ec, std::size_t bytes) {
                sp->on_write(ec, bytes);
            });
}
} // namespace sock