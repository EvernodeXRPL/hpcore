#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "public_session_handler.h"
#include "sock/socket_session.h"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

void public_session_handler::on_connect(const sock::socket_session &session, error ec)
{
}

void public_session_handler::on_message(const sock::socket_session &session, std::shared_ptr<std::string const> const &message, error ec)
{
    std::cout << "on-message : " << *message << std::endl;
}

void public_session_handler::on_close(const sock::socket_session &session)
{
    std::cout << "on_close";
}