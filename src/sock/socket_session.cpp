#include "socket_session.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../usr/user_session_handler.hpp"
#include "socket_monitor.hpp"

namespace sock
{

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

/**
 * Sets the largest permissible incoming message size. If exceeds over this limit will cause a
 * protocol failure
*/
template <class T>
void socket_session<T>::set_message_max_size(uint64_t size)
{
    ws.read_message_max(size);
}

/**
 * Set thresholds to the socket session
*/
template <class T>
void socket_session<T>::set_threshold(util::SESSION_THRESHOLDS threshold_type, uint64_t threshold_limit, uint64_t intervalms)
{
    thresholds[threshold_type].counter_value = 0;
    thresholds[threshold_type].intervalms = intervalms;
    thresholds[threshold_type].threshold_limit = threshold_limit;
}

//port and address will be used to identify from which remote party the message recieved in the handler
template <class T>
void socket_session<T>::run(const std::string &&address, const std::string &&port, bool is_server_session, const session_options &sess_opts)
{
    ssl::stream_base::handshake_type handshake_type = ssl::stream_base::client;

    if (sess_opts.max_message_size > 0)
    {
        // Setting maximum file size
        set_message_max_size(sess_opts.max_message_size);
    }

    // Create new session_threshold and insert it to thresholds array
    // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
    // since enum's value is used as index in the vector to update vector values
    session_threshold max_byte_per_message_threshold{sess_opts.max_bytes_per_minute, 0, 0, 60000};
    thresholds.push_back(std::move(max_byte_per_message_threshold));

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

    increment(util::SESSION_THRESHOLDS::MAX_BYTES_PER_MINUTE, buffer.size());

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
* Increment the provided thresholds counter value with the provided amount and validate it
*/
template <class T>
void socket_session<T>::increment(util::SESSION_THRESHOLDS threshold_type, uint64_t amount)
{
    sock::session_threshold &t = thresholds[threshold_type];

    // Ignore the counter if limit is set as 0.
    if (t.threshold_limit == 0)
        return;

    uint64_t time_now = util::get_epoch_milliseconds();

    t.counter_value += amount;
    if (t.timestamp == 0)
    {
        t.timestamp = time_now;
    }
    else
    {
        auto elapsed_time = time_now - t.timestamp;
        if (elapsed_time <= t.intervalms && t.counter_value > t.threshold_limit)
        {
            t.timestamp = 0;
            t.counter_value = 0;

            LOG_INFO << "Session " << this->uniqueid << " threshold exceeded. (type:" << threshold_type << " limit:" << t.threshold_limit << ")";

            // Invoke the threshold monitor so any actions will be performed.
            threshold_monitor(threshold_type, t.threshold_limit, this);
        }
        else if (elapsed_time > t.intervalms)
        {
            t.timestamp = time_now;
            t.counter_value = amount;
        }
    }
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
void socket_session<T>::on_close(error_code ec, int8_t type)
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

/**
 * Declaring templates with possible values for T because keeping all those in hpp file makes compile take a long time
 */
template socket_session<p2p::peer_outbound_message>::socket_session(websocket::stream<beast::ssl_stream<beast::tcp_stream>> websocket, socket_session_handler<p2p::peer_outbound_message> &sess_handler);
template socket_session<p2p::peer_outbound_message>::~socket_session();
template void socket_session<p2p::peer_outbound_message>::set_message_max_size(uint64_t size);
template void socket_session<p2p::peer_outbound_message>::run(const std::string &&address, const std::string &&port, bool is_server_session, const session_options &sess_opts);
template void socket_session<p2p::peer_outbound_message>::send(p2p::peer_outbound_message msg);
template void socket_session<p2p::peer_outbound_message>::set_threshold(util::SESSION_THRESHOLDS threshold_type, uint64_t threshold_limit, uint64_t intervalms);
template void socket_session<p2p::peer_outbound_message>::increment(util::SESSION_THRESHOLDS threshold_type, uint64_t amount);
template void socket_session<p2p::peer_outbound_message>::init_uniqueid();
template void socket_session<p2p::peer_outbound_message>::close();

template socket_session<usr::user_outbound_message>::socket_session(websocket::stream<beast::ssl_stream<beast::tcp_stream>> websocket, socket_session_handler<usr::user_outbound_message> &sess_handler);
template socket_session<usr::user_outbound_message>::~socket_session();
template void socket_session<usr::user_outbound_message>::set_message_max_size(uint64_t size);
template void socket_session<usr::user_outbound_message>::run(const std::string &&address, const std::string &&port, bool is_server_session, const session_options &sess_opts);
template void socket_session<usr::user_outbound_message>::send(usr::user_outbound_message msg);
template void socket_session<usr::user_outbound_message>::set_threshold(util::SESSION_THRESHOLDS threshold_type, uint64_t threshold_limit, uint64_t intervalms);
template void socket_session<usr::user_outbound_message>::increment(util::SESSION_THRESHOLDS threshold_type, uint64_t amount);
template void socket_session<usr::user_outbound_message>::init_uniqueid();
template void socket_session<usr::user_outbound_message>::close();

} // namespace sock