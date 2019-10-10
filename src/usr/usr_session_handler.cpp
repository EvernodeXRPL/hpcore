#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "../sock/socket_session.hpp"
#include "usr_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;
using namespace usr;

void usr_session_handler::on_connect(sock::socket_session *session, error ec)
{
}

void usr_session_handler::on_message(sock::socket_session *session, std::shared_ptr<std::string const> const &message, error ec)
{
    std::cout << "on-message : " << *message << std::endl;
}

void usr_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_close";
}