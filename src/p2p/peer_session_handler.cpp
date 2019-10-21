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

//private method used to create a proposal message with dummy data.
//Will be similiar to consensus proposal creation in each stage.
const std::string create_message()
{
    //todo:get a average propsal message size and allocate builder based on that.
    /*
    * todo: Create custom vector allocator for protobuff in order to avoid copying buffer to string.
    * Includes overidding socket_session send method to support this as well.
    */
    flatbuffers::FlatBufferBuilder builder(1024);
    std::time_t timestamp = std::time(nullptr);
    uint8_t stage = 0;

    auto pubkey = conf::cfg.pubkey;
    auto pubkey_b = builder.CreateVector((uint8_t *)pubkey.data(), pubkey.size());

    //create dummy propsal message
    auto proposal = CreateProposal(builder, pubkey_b, timestamp, stage, timestamp);
    auto message = CreateContent(builder, Message_Proposal, proposal.Union());
    builder.Finish(message); //finished building message content to get serialised content.

    //Get serialized/packed message content pointer and size.
    uint8_t *buf = builder.GetBufferPointer();
    auto size = builder.GetSize();

    //Get a binary string_view for the serialised message content.
    auto content_str = reinterpret_cast<const char *>(buf);
    std::string_view message_content(content_str, size);

    //todo: set container builder defualt builder size to combination of serialized content length + signature length(which is fixed)
    // Do this when implementing consensus.
    flatbuffers::FlatBufferBuilder container_builder(1024);

    //create container message content from serialised content from previous step.
    auto content = container_builder.CreateVector(buf, size);

    //Sign message content with node's private key.
    auto sig = crypto::sign(message_content, conf::cfg.seckey);
    auto sig_buf = sig.data();
    auto signature = container_builder.CreateVector((uint8_t *)sig_buf, sig.size()); //include signature to message

    auto container_message = CreateContainer(container_builder, util::MIN_PEERMSG_VERSION, signature, content);
    container_builder.Finish(container_message); //finished building message container to get serialised message.

    auto buf_size = container_builder.GetSize();
    auto message_buf = container_builder.GetBufferPointer();

    //todo: should return buffer_pointer to socket.
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
    // std::cout << "on-message : " << message << std::endl;
    peer_connections.insert(std::make_pair(session->uniqueid_, session));
    //session->send(std::make_shared<std::string>(message));

    //Accessing message buffer
    uint8_t *container_pointer = (uint8_t *)message.c_str();
    auto container_length = message.length();

    //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
    flatbuffers::Verifier container_verifier(container_pointer, container_length);

    //Verify container message using flatbuffer verifier
    if (VerifyContainerBuffer(container_verifier))
    {
        //Get message container
        auto container = GetContainer(container_pointer);

        auto version = container->version();

        //Get signature from message.
        auto signature = container->signature();
        auto signature_length = signature->size();
        auto signature_buf = signature->Data();

        auto signature_content_str = reinterpret_cast<const char *>(signature_buf);
        std::string_view message_signature(signature_content_str, signature_length);

        //Get serialised message content.
        auto container_content = container->content();
        auto container_content_length = container_content->size();
        auto container_content_buf = container_content->Data();

        auto message_content_str = reinterpret_cast<const char *>(container_content_buf);
        std::string_view message_content(message_content_str, container_content_length);

        //Accessing message content.
        const uint8_t *content_pointer = container_content_buf;

        //Defining Flatbuffer verifier for content message verification.
        //Since content is also serialised by using Filterbuf we can verify it using Filterbuffer.
        flatbuffers::Verifier content_verifier(content_pointer, container_content_length);

        //verify content message conent using flatbuffer verifier.
        if (VerifyContainerBuffer(content_verifier))
        {
            //Get message content.
            auto content = GetContent(content_pointer);
            auto content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

            if (content_message_type == Message_Proposal) //message is a proposal message
            {
                auto proposal = content->message_as_Proposal();
                //access proposal field data.

                //Get public key of message originating node.
                auto pubkey = proposal->pubkey();
                auto pubkey_length = pubkey->size();
                auto pubkey_buf = pubkey->Data();

                auto pubkey_str = reinterpret_cast<const char *>(pubkey_buf);
                std::string_view message_pubkey(pubkey_str, pubkey_length);

                auto timestamp = proposal->timestamp();

                //validate message for malleability, timeliness, signature and prune recieving messages.
                auto status = p2p::validate_peer_message(message_content, message_signature, message_pubkey, timestamp, version);
                //if validated send message to consensus.
                //if validated broadcast message.
            }
            else if (content_message_type == Message_Npl) //message is a proposal message
            {
                auto npl = content->message_as_Npl();
                // execute npl logic here.
                //broadcast message.
            }
            else
            {
                //warn received invalid message type from peer.
                //remove/penalize node who sent the message.
            }
        }
        else
        {
            //warn bad message from peer.
        }
    }
    else
    {
        //warn bad message from peer.
    }
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_closing peer :" + session->uniqueid_ << std::endl;
}

} // namespace p2p