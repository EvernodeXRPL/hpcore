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

//port and address will be used to identify from which client the message recieved in the handler
void socket_session::server_run(const std::uint16_t port, std::string_view address)
{
    port_ = port;
    address_ = address;

    // Accept the websocket handshake
    ws_.async_accept(
        [sp = shared_from_this()](
            error ec) {
            sp->on_accept(ec);
        });
}

//port and address will be used to identify from which server the message recieved in the handler
void socket_session::client_run(const std::uint16_t port, std::string_view address, error ec)
{
    port_ = port;
    address_ = address;

    if (ec)
        return fail(ec, "handshake");

    sess_handler_.on_connect(this);

    ws_.async_read(
        buffer_,
        [sp = shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

void socket_session::fail(error_code ec, char const *what)
{
    // std::cerr << what << ": " << ec.message() << std::endl;

    // Don't report these
    if (ec == net::error::operation_aborted ||
        ec == websocket::error::closed)
        return;
}

void socket_session::on_accept(error_code ec)
{
    // Handle the error, if any
    if (ec)
        return fail(ec, "accept");

    sess_handler_.on_connect(this);

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
    // read may get called when operation_aborted as well.
    // We don't need to process read operation in that case.
    if (ec == net::error::operation_aborted)
        return;

    // Handle the error, if any
    if (ec)
    {
        // if something goes wrong when trying to read, socket connection will be closed and calling this to inform it to the handler
        on_close(ec, 1);
        return fail(ec, "read");
    }

    std::string message = beast::buffers_to_string(buffer_.data());
    sess_handler_.on_message(this, message);

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

void socket_session::close()
{
    // Close the WebSocket connection
    ws_.async_close(websocket::close_code::normal,
                    [sp = shared_from_this()](
                        error_code ec) {
                        sp->on_close(ec, 0);
                    });
}

//type will be used identify whether the error is due to failure in closing the web socket or transfer of another exception to this method
void socket_session::on_close(error_code ec, std::int8_t type)
{
    sess_handler_.on_close(this);

    if (type == 1)
        return;

    if (ec)
        return fail(ec, "close");
}

// When called, initializes the unique id string for this session.
void socket_session::init_uniqueid()
{
    // Create a unique id for the session combining ip and port.
    // We prepare this appended string here because we need to use it for finding elemends from the maps
    // for validation purposes whenever a message is received.
    uniqueid_.append(address_).append(":").append(std::to_string(port_));
}

} // namespace sock