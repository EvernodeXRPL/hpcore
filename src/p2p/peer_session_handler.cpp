#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "message.pb.h"
#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace p2p
{
peer_session_handler peer_session_manager;
std::time_t timestamp = std::time(nullptr);

//peer session on connect callback method
void peer_session_handler::on_connect(sock::socket_session *session)
{
    std::cout << "Sending message" << std::endl;
    auto const message = std::make_shared<std::string const>("Connected successfully");
    //session->send(message);
    //todo:check connected peer is in peer list.
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session *session, const std::string &message)
{
    std::cout << "on-message : " << message << std::endl;
    session->send(std::make_shared<std::string>(message));
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_close";
}

void open_listen()
{

    auto address = net::ip::make_address("0.0.0.0");
    net::io_context ioc;

    // std::make_shared<sock::socket_server>(
    //     ioc,
    //     tcp::endpoint{address, 22860},
    //     peer_session_manager)
    //     ->run();

    std::make_shared<sock::socket_client>(ioc, peer_session_manager)->run((conf::cfg.listenip).c_str(), "22860");

    std::thread run_thread([&] { ioc.run(); });
    int t;
    std::cin >> t;
}

bool validate_peer_message(const Message &peer_message, const std::string &message)
{
    //todo:check pubkey in unl list. need to change unl list to a map.

    //check message timestamp < timestamp now - 4* round time
    if (peer_message.timestamp() < (timestamp - conf::cfg.roundtime * 4))
    {
        std::cout << "recieved message from peer is old" << std::endl;
        return false;
    }

    //get message hash and see wheteher message is already recieved -> abandon
    auto messageHash = crypto::sha_512_hash(message, "PEERMSG", 7);

    if (peer_ctx.recent_peer_msghash.count(messageHash) == 0)
    {
        peer_ctx.recent_peer_msghash.insert({messageHash, timestamp});
    }
    else
    {
        return false;
    }

    //check signature
    //todo:move to initial part.

    return true;
}

void on_peer_message_recieved(const std::string &message)
{
    Message container_message;

    if (message_parse_from_string(container_message, message))
    {
        if (validate_peer_message(container_message, message))
        {
            auto messageType = container_message.type();
            if (messageType == p2p::Message::PROPOSAL)
            {
                //put it into propsal message map
                //broadcast it
            }
            else if (messageType == p2p::Message::NPL)
            {
                //put it into npl list
                //broadcast it
            }
            else
            {
            }
        }
    }
    else
    {
        //bad message
    }
}

} // namespace p2p