#ifndef _SOCK_SERVER_LISTENER_H_
#define _SOCK_SERVER_LISTENER_H_

#include <boost/asio.hpp>

namespace net = boost::asio;                    // namespace asio

using tcp = net::ip::tcp;
using error = boost::system::error_code; // from <boost/system/error_code.hpp>

// namespace sock
// {

// Forward declaration
class shared_state;

// Accepts incoming connections and launches the sessions
class server_listener : public std::enable_shared_from_this<server_listener>
{
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::shared_ptr<shared_state> state_;

    void fail(error ec, char const *what);
    void on_accept(error ec);

public:
    server_listener(
        net::io_context &ioc,
        tcp::endpoint endpoint,
        std::shared_ptr<shared_state> const &state);

    // Start accepting incoming connections
    void run();
};
//} // namespace sock

#endif