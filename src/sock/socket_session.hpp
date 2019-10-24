#ifndef _SOCK_SERVER_SESSION_H_
#define _SOCK_SERVER_SESSION_H_

#include <memory>
#include <vector>
#include <bitset>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include "socket_session_handler.hpp"
#include "../util.hpp"
#include "../hplog.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace sock
{

/**
 * Represents an outbound message that is sent with a websocket.
 * We use this class to wrap different object types holding actual message contents.
 * We use this mechanism to achieve end-to-end zero-copy between original message
 * content generator and websocket flush.
 */
class outbound_message
{
public:
    // Returns a pointer to the internal buffer owned by the message object.
    // Contents of this buffer is the message that is sent/received with the socket.
    virtual std::string_view buffer() = 0;
};

// Use this to feed the session with default options from the config file
struct session_options
{
    std::uint64_t max_message_size; // The CLI command issued to launch HotPocket
};

extern session_options sess_opts;

//Forward Declaration
template <class T>
class socket_session_handler;

/** 
 * Represents an active WebSocket connection
*/
template <class T>
class socket_session : public std::enable_shared_from_this<socket_session<T>>
{
    beast::flat_buffer buffer;                                  // used to store incoming messages
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws; // websocket stream used send an recieve messages
    std::vector<T> queue;                                       // used to store messages temporarily until it is sent to the relevant party
    socket_session_handler<T> &sess_handler;                    // handler passed to gain access to websocket events

    void fail(error_code ec, char const *what);

    void on_ssl_handshake(error_code ec);

    void on_accept(error_code ec);

    void on_read(error_code ec, std::size_t bytes_transferred);

    void on_write(error_code ec, std::size_t bytes_transferred);

    void on_close(error_code ec, std::int8_t type);

public:
    socket_session(websocket::stream<beast::ssl_stream<beast::tcp_stream>> websocket, socket_session_handler<T> &sess_handler);

    ~socket_session();

    // Port and the address of the remote party is being saved to used in the session handler
    // to identify from which remote party the message recieved. Since the port is passed as a string
    // from the parent we store as it is, since we are not going to pass it anywhere or used in a method

    // The port of the remote party.
    std::string port;

    // The IP address of the remote party.
    std::string address;

    // The unique identifier of the remote party (format <ip>:<port>).
    std::string uniqueid;

    // The set of util::SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    void run(const std::string &&address, const std::string &&port, const bool is_server_session, const session_options &sess_opts);

    void send(T msg);

    void set_message_max_size(std::uint64_t size);

    // When called, initializes the unique id string for this session.
    void init_uniqueid();

    void close();
};

template <class T>
socket_session<T>::socket_session(websocket::stream<beast::ssl_stream<beast::tcp_stream>> websocket, socket_session_handler<T> &sess_handler)
    : ws(std::move(websocket)), sess_handler(sess_handler)
{
    // We use binary data instead of ASCII/UTF8 character data.
    ws.binary(true);
}

template <class T>
socket_session<T>::~socket_session()
{
    sess_handler.on_close(this);
}

template <class T>
void socket_session<T>::set_message_max_size(std::uint64_t size)
{
    ws.read_message_max(size);
}

//port and address will be used to identify from which remote party the message recieved in the handler
template <class T>
void socket_session<T>::run(const std::string &&address, const std::string &&port, const bool is_server_session, const session_options &sess_opts)
{
    ssl::stream_base::handshake_type handshake_type = ssl::stream_base::client;

    std::cout << "Message size :" << sess_opts.max_message_size << std::endl;
    // If message max size is defined in the session_options struct set it to the websocket stream
    if (sess_opts.max_message_size > 0)
        set_message_max_size(sess_opts.max_message_size);

    if (is_server_session)
    {
        /**
         * Set this flag to identify whether this socket session created when node acts as a server
         * INBOUND true - when node acts as server
         * INBOUND false (OUTBOUND) - when node acts as client
         */
        flags.set(util::SESSION_FLAG::INBOUND);
        handshake_type = ssl::stream_base::server;
    }

    this->port = port;
    this->address = address;

    // Set the timeout.
    beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    ws.next_layer().async_handshake(
        handshake_type,
        [sp = this->shared_from_this()](error_code ec) {
            sp->on_ssl_handshake(ec);
        });
}

/*
* Close an active websocket connection gracefully
*/
template <class T>
void socket_session<T>::on_ssl_handshake(error_code ec)
{
    if (ec)
        return fail(ec, "handshake");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    beast::get_lowest_layer(ws).expires_never();

    if (flags[util::SESSION_FLAG::INBOUND])
    {
        // Set suggested timeout settings for the websocket
        ws.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // Accept the websocket handshake
        ws.async_accept(
            [sp = this->shared_from_this()](
                error_code ec) {
                sp->on_accept(ec);
            });
    }
    else
    {

        ws.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::client));

        // Perform the websocket handshake
        ws.async_handshake(this->address, "/",
                           [sp = this->shared_from_this()](
                               error_code ec) {
                               sp->on_accept(ec);
                           });
    }
}

/**
 * Executes on acceptance of new connection
*/
template <class T>
void socket_session<T>::on_accept(error_code ec)
{
    // Handle the error, if any
    if (ec)
        return fail(ec, "accept");

    sess_handler.on_connect(this);

    // Read a message
    ws.async_read(
        buffer,
        [sp = this->shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

/*
* Executes on completion of recieiving a new message
*/
template <class T>
void socket_session<T>::on_read(error_code ec, std::size_t)
{
    //if something goes wrong when trying to read, socket connection will be closed and calling this to inform it to the handler
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

    // Wrap the buffer data in a string_view and call session handler.
    // We DO NOT transfer ownership of buffer data to the session handler. It should
    // read and process the message and we will clear the buffer after its done with it.
    const char *buffer_data = net::buffer_cast<const char *>(buffer.data());
    std::string_view message(buffer_data, buffer.size());
    sess_handler.on_message(this, message);

    // Clear the buffer
    buffer.consume(buffer.size());

    // Read another message
    ws.async_read(
        buffer,
        [sp = this->shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_read(ec, bytes);
        });
}

/*
* Send message through an active websocket connection
*/
template <class T>
void socket_session<T>::send(T msg)
{
    // Always add to queue
    queue.push_back(std::move(msg));

    // Are we already writing?
    if (queue.size() > 1)
        return;

    std::string_view sv = queue.front().buffer();

    // We are not currently writing, so send this immediately
    ws.async_write(
        // Project the outbound_message buffer from the queue front into the asio buffer.
        net::buffer(sv.data(), sv.length()),
        [sp = this->shared_from_this()](
            error_code ec, std::size_t bytes) {
            sp->on_write(ec, bytes);
        });
}

/*
* Executes on completion of write operation to a socket
*/
template <class T>
void socket_session<T>::on_write(error_code ec, std::size_t)
{
    // Handle the error, if any
    if (ec)
        return fail(ec, "write");

    // Remove the string from the queue
    queue.erase(queue.begin());

    // Send the next message if any
    if (!queue.empty())
    {
        std::string_view sv = queue.front().buffer();
        ws.async_write(
            net::buffer(sv.data(), sv.length()),
            [sp = this->shared_from_this()](
                error_code ec, std::size_t bytes) {
                sp->on_write(ec, bytes);
            });
    }
}

/*
* Close an active websocket connection gracefully
*/
template <class T>
void socket_session<T>::close()
{
    // Close the WebSocket connection
    ws.async_close(websocket::close_code::normal,
                   [sp = this->shared_from_this()](
                       error_code ec) {
                       sp->on_close(ec, 0);
                   });
}

/*
* Executes on completion of closing a socket connection
*/
//type will be used identify whether the error is due to failure in closing the web socket or transfer of another exception to this method
template <class T>
void socket_session<T>::on_close(error_code ec, std::int8_t type)
{
    if (type == 1)
        return;

    if (ec)
        return fail(ec, "close");
}

// When called, initializes the unique id string for this session.
template <class T>
void socket_session<T>::init_uniqueid()
{
    // Create a unique id for the session combining ip and port.
    // We prepare this appended string here because we need to use it for finding elemends from the maps
    // for validation purposes whenever a message is received.
    uniqueid.append(address).append(":").append(port);
}

/**
 * Executes on error
*/
template <class T>
void socket_session<T>::fail(error_code ec, char const *what)
{
    LOG_ERR << what << ": " << ec.message();

    // Don't report these
    if (ec == net::error::operation_aborted ||
        ec == websocket::error::closed)
        return;
}

} // namespace sock
#endif
