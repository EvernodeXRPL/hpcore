#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"
#include "flatbuffers/flatbuffers.h"
#include "message_content_generated.h"
#include "message_container_generated.h"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace p2p
{

const uint8_t* create_message()
{
    flatbuffers::FlatBufferBuilder builder(1024);
    std::time_t timestamp = std::time(nullptr);
    uint8_t stage = 0;

    auto proposal = CreateProposal(builder, 0, timestamp, stage, timestamp);
    auto message = CreateContent(builder, Message_NONE, proposal.Union());
    builder.Finish(message);
    //builder.
    uint8_t *buf = builder.GetBufferPointer();
    auto size = builder.GetSize();

    auto messageContent = GetContent(buf);
    flatbuffers::FlatBufferBuilder container_builder(1024);

    auto content = container_builder.CreateVector(buf, size);

    auto container_message = CreateContainer(container_builder, 0, 0, content);
    container_builder.Finish(container_message);
    return container_builder.GetBufferPointer();
}

//peer session on connect callback method
void peer_session_handler::on_connect(sock::socket_session *session)
{
    std::cout << "Sending message" << std::endl;
    auto const message = std::make_shared<std::string const>("Connected successfully");
    //auto const message1 = create_message();
    //session->send(std::make_shared<std::string const>(message1));
    //todo:check connected peer is in peer list.
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session *session, const std::string &message)
{
    std::cout << "on-message : " << message << std::endl;
    //session->send(std::make_shared<std::string>(message));
    uint8_t *container_pointer = (uint8_t *)message.c_str();
    auto container_length = message.length();

    std::cout << "on-message : " << *container_pointer << std::endl;
    //Message container_message;

    //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
    flatbuffers::Verifier container_verifier(container_pointer, container_length);

    //verify message conent using flatbuffer verifier
    if (VerifyContainerBuffer(container_verifier))
    {
        auto container = GetContainer(container_pointer);


        auto version = container->version();
        auto signature = container->signature();
        auto container_content = container->content();
        auto container_content_length = container_content->size();
        auto container_content_str = container_content->GetAsString(container_content_length);

        //validate message
        uint8_t *content_pointer = (uint8_t *)container_content;

        //Defining Flatbuffer verifier for content verification.
        flatbuffers::Verifier content_verifier(container_pointer, container_length);

        //verify message conent using flatbuffer
        if (VerifyContainerBuffer(content_verifier))
        {
            auto content = GetMutableContent(content_pointer);
            auto content_message_type = content->message_type();

            if (content_message_type == Message_Proposal)
            {
                auto proposal = content->message_as_Proposal();
                //call message validate method
                //if so  call send message to consensus
            }
            else if (content_message_type == Message_Npl)
            {
                auto npl = content->message_as_Npl();

                // //put it into npl list
                // p2p::peer_ctx.npl_messages.push_back(npl);
                //broadcast it
            }
            else
            {
            }
        }
    }
    else
    {
    }

} // namespace p2p

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_close";
}

} // namespace p2p