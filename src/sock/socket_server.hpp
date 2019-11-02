#ifndef _HP_SOCKET_SERVER_
#define _HP_SOCKET_SERVER_

#include "socket_session_handler.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"

namespace net = boost::asio;      // namespace asio
namespace ssl = boost::asio::ssl;

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace sock
{

/** 
 * Represents an active WebSocket server connection
 * Based on the implementation from https://github.com/vinniefalco/CppCon2018
*/
template <class T>
class socket_server : public std::enable_shared_from_this<socket_server<T>>
{
    tcp::acceptor acceptor;                  // acceptor which accepts new connections
    net::io_context &ioc;                    // socket in which the client connects
    ssl::context &ctx;                       // ssl context which provides support for tls
    socket_session_handler<T> &sess_handler; // handler passed to gain access to websocket events
    const session_options &sess_opts;              // session options needed to pass to session

    void fail(error_code ec, char const *what);

    void on_accept(error_code ec, tcp::socket socket);

public:
    socket_server(net::io_context &ioc, ssl::context &ctx, tcp::endpoint endpoint, socket_session_handler<T> &session_handler, const session_options &session_options);

    // Start accepting incoming connections
    void run();
};


} // namespace sock

#endif