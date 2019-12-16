#include "../bill/corebill.h"
#include "socket_session.hpp"
#include "socket_message.hpp"
#include "socket_session_handler.hpp"

namespace sock
{

// Constructor
template <class T>
socket_session<T>::socket_session(websocket::stream<beast::ssl_stream<beast::tcp_stream>> websocket, socket_session_handler<T> &sess_handler)
    : ws(std::move(websocket)), sess_handler(sess_handler)
{
    // We use binary data instead of ASCII/UTF8 character data.
    ws.binary(true);
}

/**
 * Sets the largest permissible incoming data length in a single receive. If exceeds over this limit will cause
 * a protocol failure. Because this is internally handled by beast socket, we don't use socket_threshold struct
 * to handle this.
*/
template <class T>
void socket_session<T>::set_max_socket_read_len(const uint64_t size)
{
    ws.read_message_max(size);
}

/**
 * Set thresholds to the socket session
*/
template <class T>
void socket_session<T>::set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms)
{
    session_threshold &t = thresholds[threshold_type];
    t.counter_value = 0;
    t.intervalms = intervalms;
    t.threshold_limit = threshold_limit;
}

/*
* Increment the provided thresholds counter value with the provided amount and validate it against the
* configured threshold limit.
*/
template <class T>
void socket_session<T>::increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount)
{
    session_threshold &t = thresholds[threshold_type];

    // Ignore the counter if limit is set as 0.
    if (t.threshold_limit == 0)
        return;

    const uint64_t time_now = util::get_epoch_milliseconds();

    t.counter_value += amount;
    if (t.timestamp == 0)
    {
        // Reset counter timestamp.
        t.timestamp = time_now;
    }
    else
    {
        // Check whether we have exceeded the threshold within the monitering interval.
        const uint64_t elapsed_time = time_now - t.timestamp;
        if (elapsed_time <= t.intervalms && t.counter_value > t.threshold_limit)
        {
            this->close();

            t.timestamp = 0;
            t.counter_value = 0;

            LOG_INFO << "Session " << this->uniqueid << " threshold exceeded. (type:" << threshold_type << " limit:" << t.threshold_limit << ")";
            corebill::report_violation(this->address);
        }
        else if (elapsed_time > t.intervalms)
        {
            t.timestamp = time_now;
            t.counter_value = amount;
        }
    }
}

//port and address will be used to identify from which remote party the message recieved in the handler
template <class T>
void socket_session<T>::run(const std::string &&address, const std::string &&port, const bool is_server_session, const session_options &sess_opts)
{
    if (sess_opts.max_socket_read_len > 0)
    {
        // Setting maximum data size within a single message. This is handled within the beast socket.
        set_max_socket_read_len(sess_opts.max_socket_read_len);
    }

    // Create new session_thresholds and insert it to thresholds vector.
    // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
    // since enum's value is used as index in the vector to update vector values.
    thresholds.reserve(4);
    thresholds.push_back(session_threshold(sess_opts.max_rawbytes_per_minute, 60000));
    thresholds.push_back(session_threshold(sess_opts.max_dupmsgs_per_minute, 60000));
    thresholds.push_back(session_threshold(sess_opts.max_badsigmsgs_per_minute, 60000));
    thresholds.push_back(session_threshold(sess_opts.max_badmsgs_per_minute, 60000));

    const ssl::stream_base::handshake_type handshake_type =
        is_server_session ? ssl::stream_base::server : ssl::stream_base::client;

    // Set this flag to identify whether this socket session created when node acts as a server
    // INBOUND true - when node acts as server
    // INBOUND false (OUTBOUND) - when node acts as client
    if (is_server_session)
        flags.set(SESSION_FLAG::INBOUND);

    this->port = std::move(port);
    this->address = std::move(address);

    // Create a unique id for the session combining ip and port.
    // We prepare this appended string here because we need to use it as an identifier of the session in various places.
    this->uniqueid.reserve(port.size() + address.size() + 1);
    this->uniqueid.append(address).append(":").append(port);

    // This indicates the connection is a self connection (node connects to the same node through server port)
    if (address == "0.0.0.0")
        this->is_self = true;

    // Set the timeout.
    beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    ws_next_layer_async_handshake(handshake_type);
}

/*
* Close an active websocket connection gracefully
*/
template <class T>
void socket_session<T>::on_ssl_handshake(const error_code ec)
{
    if (ec)
        return fail(ec, "handshake");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    beast::get_lowest_layer(ws).expires_never();

    if (flags[SESSION_FLAG::INBOUND])
    {
        // Set suggested timeout settings for the websocket
        ws.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // Accept the websocket handshake
        ws_async_accept();
    }
    else
    {
        ws.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::client));

        // Perform the websocket handshake
        ws_async_handshake();
    }
}

/**
 * Executes on acceptance of new connection
*/
template <class T>
void socket_session<T>::on_accept(const error_code ec)
{
    // Handle the error, if any
    if (ec)
        return fail(ec, "accept");

    if (corebill::is_banned(this->address))
    {
        LOG_DBG << "Dropping connection for banned host " << this->address;
        this->close();
    }

    sess_handler.on_connect(this);

    // Read a message
    ws_async_read();
}

/*
* Executes on completion of recieiving a new message
*/
template <class T>
void socket_session<T>::on_read(const error_code ec, const std::size_t)
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

    increment_metric(SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, buffer.size());

    // Wrap the buffer data in a string_view and call session handler.
    // We DO NOT transfer ownership of buffer data to the session handler. It should
    // read and process the message and we will clear the buffer after its done with it.
    const char *buffer_data = net::buffer_cast<const char *>(buffer.data());
    std::string_view message(buffer_data, buffer.size());
    sess_handler.on_message(this, message);

    // Clear the buffer
    buffer.consume(buffer.size());

    // Read another message
    ws_async_read();
}

/*
* Send message through an active websocket connection
*/
template <class T>
void socket_session<T>::send(const T msg)
{
    try
    {
        std::lock_guard<std::mutex> lock(send_mutex);

        // Always add to queue
        queue.push_back(std::move(msg));
        //using sync write until async_write is properly handled for multi-threaded writes.
        ws.write(net::buffer(queue.front().buffer()));
        queue.erase(queue.begin());
    }
    catch (...)
    {
        this->handle_exception("sync_write");
    }

    // Are we already writing?
    // if (queue.size() > 1)
    //     return;

    // std::string_view sv = queue.front().buffer();

    // // We are not currently writing, so send this immediately
    // ws_async_write(sv);
}

/*
* Executes on completion of write operation to a socket
*/
template <class T>
void socket_session<T>::on_write(const error_code ec, const std::size_t)
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
        ws_async_write(sv);
    }
}

/*
* Close an active websocket connection gracefully
*/
template <class T>
void socket_session<T>::close()
{
    // Close the WebSocket connection
    ws_async_close();
}

/*
* Executes on completion of closing a socket connection
*/
//type will be used identify whether the error is due to failure in closing the web socket or transfer of another exception to this method
template <class T>
void socket_session<T>::on_close(const error_code ec, const int8_t type)
{
    sess_handler.on_close(this);

    if (type == 1)
        return;

    if (ec)
        return fail(ec, "close");
}

/**
 * Executes on error
*/
template <class T>
void socket_session<T>::fail(const error_code ec, char const *what)
{
    LOG_ERR << what << ": " << ec.message();

    // Don't report these
    if (ec == net::error::operation_aborted ||
        ec == websocket::error::closed)
        return;
}

template <class T>
void socket_session<T>::handle_exception(std::string_view event_name)
{
    std::exception_ptr p = std::current_exception();
    LOG_ERR << "Socket Exception on " << event_name << ": " << (p ? p.__cxa_exception_type()->name() : "null") << std::endl;

    // Close the socket on any event error except close event.
    if (event_name != "close")
        this->ws_async_close();
}

template <class T>
socket_session<T>::~socket_session()
{
    sess_handler.on_close(this);
}

// Template instantiations.
template class socket_session<p2p::peer_outbound_message>;
template class socket_session<usr::user_outbound_message>;

} // namespace sock