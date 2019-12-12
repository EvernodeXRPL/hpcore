#ifndef _HP_SOCKET_SESSION_
#define _HP_SOCKET_SESSION_

#include "../pchheader.hpp"
#include "../util.hpp"
#include "../hplog.hpp"

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
using error_code = boost::system::error_code;

namespace sock
{

/**
 * Set of flags used to mark status information on the session.
 * usr and p2p subsystems makes use of this to mark status information of user and peer sessions.
 * Set flags are stored in 'flags' bitset of socket_session.
 */
enum SESSION_FLAG
{
    INBOUND = 0,
    USER_CHALLENGE_ISSUED = 1,
    USER_AUTHED = 2
};

/**
 * Enum used to track down various thresholds used in socket communication.
 */
enum SESSION_THRESHOLDS
{
    // Max incoming bytes per minute.
    MAX_RAWBYTES_PER_MINUTE = 0,

    // Max duplicate messages per minute.
    MAX_DUPMSGS_PER_MINUTE = 1,

    // Max messages with invalid signature per minute.
    MAX_BADSIGMSGS_PER_MINUTE = 2,

    // Max messages with bad structure per minute.
    MAX_BADMSGS_PER_MINUTE = 3
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
    uint32_t intervalms;

    session_threshold(uint64_t threshold_limit, uint32_t intervalms)
    {
        this->threshold_limit = threshold_limit;
        this->intervalms = intervalms;
    }
};

// Use this to feed the session with default options from the config file
struct session_options
{
    uint64_t max_socket_read_len;
    uint64_t max_rawbytes_per_minute;
    uint64_t max_dupmsgs_per_minute;
    uint64_t max_badsigmsgs_per_minute;
    uint64_t max_badmsgs_per_minute;
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
    std::queue<T> dispatch_queue;                                        // used to store messages temporarily until it is sent to the relevant party
    bool is_dispatching = false;
    socket_session_handler<T> &sess_handler;                    // handler passed to gain access to websocket events
    std::vector<session_threshold> thresholds;                  // track down various communication thresholds 
    
    static std::thread dispatcher_thread;
    static std::unordered_map<socket_session<T> *, std::queue<T>> dispatch_pending_sessions;
    static std::mutex dispatch_pending_sessions_mutex;

    void fail(const error_code ec, char const *what);

    void on_ssl_handshake(const error_code ec);

    void on_accept(const error_code ec);

    void on_read(const error_code ec, const std::size_t bytes_transferred);

    void on_write(const error_code ec, const std::size_t bytes_transferred);

    void on_close(const error_code ec, const int8_t type);


    // Websocket lambda expression helpers.
    // Implementation of these are separated to a different .cpp to reduce regular compile time.

    void ws_next_layer_async_handshake(const ssl::stream_base::handshake_type handshake_type);

    void ws_async_accept();

    void ws_async_handshake();

    void ws_async_read();

    void ws_async_write(std::string_view message);

    void ws_async_close();

    void dispatch();

    static void run_dispatcher();

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

    // Boolean value to store whether the session is self connection (connect to the same node)
    bool is_self;

    // The set of sock::SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    void set_max_socket_read_len(const uint64_t size);

    void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);

    void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);

    void run(const std::string &&address, const std::string &&port, const bool is_server_session, const session_options &sess_opts);

    void send(const T msg);

    void close();

    static void init_dispatcher();
};

} // namespace sock
#endif
