#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "peer_session_handler.h"
#include "sock/socket_session.h"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

void peer_session_handler::on_connect(sock::socket_session *session, error ec)
{
    auto const message = std::make_shared<std::string const>("Connected successfully");
    session->send(message);
}

void peer_session_handler::on_message(sock::socket_session *session, std::shared_ptr<std::string const> const &message, error ec)
{
    std::cout << "on-message : " << *message << std::endl;
    session->send(message);
}

void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_close";
}