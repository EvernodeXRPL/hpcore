#include <iostream>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "p2p.hpp"
#include "../util.hpp"
#include "peer_session_handler.hpp"
#include "flatbuffers/flatbuffers.h"
#include "message_content_generated.h"
#include "message_container_generated.h"

namespace p2p
{
const std::string create_message()
{
    //todo:get a average propsal message size and allocate builder based on that.
    //todo: Create custom vector allocator in order to avoid copying buffer to string.

    flatbuffers::FlatBufferBuilder builder(1024);
    std::time_t timestamp = std::time(nullptr);
    uint8_t stage = 0;

    auto pubkey = builder.CreateVector((uint8_t *)conf::cfg.pubkey.data(), conf::cfg.pubkey.size());
    auto proposal = CreateProposal(builder, pubkey, timestamp, stage, timestamp);
    auto message = CreateContent(builder, Message_Proposal, proposal.Union());
    builder.Finish(message);

    //builder.
    uint8_t *buf = builder.GetBufferPointer();
    auto size = builder.GetSize();

    flatbuffers::FlatBufferBuilder container_builder(1024);

    auto content = container_builder.CreateVector(buf, size);
    auto container_message = CreateContainer(container_builder, 5, content, content);
    container_builder.Finish(container_message);
    auto buf_size = container_builder.GetSize();
    auto message_buf = container_builder.GetBufferPointer();

    //todo: should return buffer_pointer to socket
    return std::string((char *)message_buf, buf_size);
}

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(sock::socket_session *session)
{
    if (!session->flags_[util::SESSION_FLAG::INBOUND])
    {
        // We init the session unique id to associate with the challenge.
        session->init_uniqueid();
        peer_connections.insert(std::make_pair(session->uniqueid_, session));
        std::cout << "Adding peer to list :" << session->uniqueid_ + " " << session->address_ + " " << session->port_ << std::endl;
    }
    else
    {
        std::string message = create_message();
        // std::cout << "Sending message :" << message << std::endl;
        // std::string message = "I'm " + conf::cfg.listenip + ":" + std::to_string(conf::cfg.peerport);
        session->send(std::move(message));
    }
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session *session, std::string &&message)
{
    std::cout << "on-message : " << message << std::endl;
    peer_connections.insert(std::make_pair(session->uniqueid_, session));
    //session->send(std::make_shared<std::string>(message));

    uint8_t *container_pointer = (uint8_t *)message.c_str();
    auto container_length = message.length();

    //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
    flatbuffers::Verifier container_verifier(container_pointer, container_length);

    //Verify container message conent using flatbuffer verifier
    if (VerifyContainerBuffer(container_verifier))
    {
        auto container = GetContainer(container_pointer);

        auto version = container->version();
        auto signature = container->signature();
        std::cout << "version" << version << std::endl;
        auto container_content = container->content();
        auto container_content_length = container_content->size();
        auto container_content_buf = container_content->Data();

        // auto container_content_str = container_content->GetAsString(container_content_length);

        //validate message
        const uint8_t *content_pointer = container_content_buf;

        //Defining Flatbuffer verifier for content message verification.
        //Since content is also serialised by using Filterbuf we can verify it using Filterbuffer.
        flatbuffers::Verifier content_verifier(content_pointer, container_content_length);

        //verify content message conent using flatbuffer.
        if (VerifyContainerBuffer(content_verifier))
        {
            auto content = GetContent(content_pointer);
            auto content_message_type = content->message_type();
            std::cout << "asa2:" << std::to_string(content_message_type) << std::endl;
            if (content_message_type == Message_Proposal)
            {
                auto proposal = content->message_as_Proposal();
                auto pubkey = proposal->pubkey();
                auto pubkey_p = pubkey->data();
                auto timestamp = proposal->timestamp();
                std::cout << "timestamp:" << timestamp << std::endl;

                //call message validate method
                //p2p::validate_peer_message(container_content_str->string_view(), timestamp, version, pubkey->GetAsString()->string_view());
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
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_closing peer :" + session->uniqueid_ << std::endl;
}

} // namespace p2p