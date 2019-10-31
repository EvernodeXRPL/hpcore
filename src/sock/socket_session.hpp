#ifndef _SOCK_SERVER_SESSION_H_
#define _SOCK_SERVER_SESSION_H_

#include <memory>
#include <vector>
#include <bitset>
#include <unordered_map>
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

/*
* Use this to keep in track of different thresholds which we need to deal with. e.g - maximum amount of bytes allowed per minute through a session
* threshold_limit - Maximum threshold value which is allowed
* counter_value - Counter which keeps incrementing per every message
* timestamp - Timestamp when counter value changes
* intervalms - Time interval in miliseconds in which the threshold and the counter value should be compared
*/
struct session_threshold
{
    uint64_t threshold_limit;
    uint64_t counter_value;
    uint64_t timestamp;
    uint64_t intervalms;

    // session_threshold(uint64_t threshold_limit, uint64_t intervalms)
    //     : threshold_limit(threshold_limit), intervalms(intervalms), counter_value(0), timestamp(0) {}
};

// Use this to feed the session with default options from the config file
struct session_options
{
    uint64_t max_message_size;
    uint64_t max_bytes_per_minute;
};

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
    std::vector<session_threshold> thresholds;                  // track down various thresholdsls

    void fail(error_code ec, char const *what);

    void on_ssl_handshake(error_code ec);

    void on_accept(error_code ec);

    void on_read(error_code ec, std::size_t bytes_transferred);

    void on_write(error_code ec, std::size_t bytes_transferred);

    void on_close(error_code ec, int8_t type);
   

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

    void run(const std::string &&address, const std::string &&port, bool is_server_session, const session_options &sess_opts);

    void send(T msg);

    void set_message_max_size(uint64_t size);

    void set_threshold(util::SESSION_THRESHOLDS threshold_type, uint64_t threshold_limit, uint64_t interval);

     void increment(util::SESSION_THRESHOLDS threshold_type, uint64_t amount);

    // When called, initializes the unique id string for this session.
    void init_uniqueid();

    void close();
};

} // namespace sock
#endif
