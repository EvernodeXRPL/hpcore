#include <iostream>
#include <flatbuffers/flatbuffers.h>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"
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
    * todo: create custom vector allocator for protobuff in order to avoid copying buffer to string.
    * includes overidding socket_session send method to support this as well.
    */
    flatbuffers::FlatBufferBuilder builder(1024);
    std::time_t timestamp = std::time(nullptr);
    uint8_t stage = 0;

    std::string pubkey = conf::cfg.pubkey;
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pubkey_b = builder.CreateVector((uint8_t *)pubkey.data(), pubkey.size());

    //create dummy propsal message
    flatbuffers::Offset<Proposal> proposal = CreateProposal(builder, pubkey_b, timestamp, stage, timestamp);
    flatbuffers::Offset<Content> message = CreateContent(builder, Message_Proposal, proposal.Union());
    builder.Finish(message); //finished building message content to get serialised content.

    //Get serialized/packed message content pointer and size.
    uint8_t *buf = builder.GetBufferPointer();
    flatbuffers::uoffset_t size = builder.GetSize();

    //Get a binary string_view for the serialised message content.
    const char *content_str = reinterpret_cast<const char *>(buf);
    std::string_view message_content(content_str, size);

    //todo: set container builder defualt builder size to combination of serialized content length + signature length(which is fixed)
    // Do this when implementing consensus.
    flatbuffers::FlatBufferBuilder container_builder(1024);

    //create container message content from serialised content from previous step.
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> content = container_builder.CreateVector(buf, size);

    //Sign message content with node's private key.
    std::string sig = crypto::sign(message_content, conf::cfg.seckey);
    char *sig_buf = sig.data();
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> signature = container_builder.CreateVector((uint8_t *)sig_buf, sig.size()); //include signature to message

    flatbuffers::Offset<Container> container_message = CreateContainer(container_builder, util::MIN_PEERMSG_VERSION, signature, content);
    container_builder.Finish(container_message); //finished building message container to get serialised message.

    flatbuffers::uoffset_t buf_size = container_builder.GetSize();
    uint8_t *message_buf = container_builder.GetBufferPointer();

    //todo: should return buffer_pointer to socket.
    return std::string((char *)message_buf, buf_size);
}

/**
 * Private method to return string_view from flat buffer data pointer and length.
 */
std::string_view flatbuff_bytes_to_sv(const uint8_t *data, flatbuffers::uoffset_t length)
{
    const char *signature_content_str = reinterpret_cast<const char *>(data);
    return std::string_view(signature_content_str, length);
}

/**
 * Private method to return string_view from Flat Buffer vector of bytes.
 */
std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer)
{
    return flatbuff_bytes_to_sv(buffer->Data(), buffer->size());
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
        LOG_DBG << "Adding peer to list :" << session->uniqueid_ + " " << session->address_ + " " << session->port_;
    }
    else
    {
        std::string message = create_message();
        session->send(std::move(message));
    }
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session *session, std::string_view message)
{
    peer_connections.insert(std::make_pair(session->uniqueid_, session));

    //Accessing message buffer
    const uint8_t *container_pointer = reinterpret_cast<const uint8_t *>(message.data());
    size_t container_length = message.length();

    //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
    flatbuffers::Verifier container_verifier(container_pointer, container_length);

    //Verify container message using flatbuffer verifier
    if (VerifyContainerBuffer(container_verifier))
    {
        //Get message container
        const p2p::Container *container = GetContainer(container_pointer);
        const uint16_t version = container->version();

        //Get serialised message content.
        const flatbuffers::Vector<uint8_t> *container_content = container->content();

        //Accessing message content and size.
        const uint8_t *content_pointer = container_content->Data();
        flatbuffers::uoffset_t content_size = container_content->size();

        //Defining Flatbuffer verifier for content message verification.
        //Since content is also serialised by using Filterbuf we can verify it using Filterbuffer.
        flatbuffers::Verifier content_verifier(content_pointer, content_size);

        //verify content message conent using flatbuffer verifier.
        if (VerifyContainerBuffer(content_verifier))
        {
            //Get message content.
            const Content *content = GetContent(content_pointer);
            p2p::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

            if (content_message_type == Message_Proposal) //message is a proposal message
            {
                const Proposal *proposal = content->message_as_Proposal();
                uint64_t timestamp = proposal->timestamp();

                //Get public key of message originating node.
                std::string_view message_pubkey = flatbuff_bytes_to_sv(proposal->pubkey());

                //Get signature from container message.
                std::string_view message_signature = flatbuff_bytes_to_sv(container->signature());

                std::string_view message_content = flatbuff_bytes_to_sv(content_pointer, content_size);

                //validate message for malleability, timeliness, signature and prune recieving messages.
                bool validated = p2p::validate_peer_message(message_content, message_signature, message_pubkey, timestamp, version);
                if (validated)
                {
                    //if validated send message to consensus.
                    //if validated broadcast message.
                }
                else
                {
                    LOG_DBG << "Message validation failed";
                }
            }
            else if (content_message_type == Message_Npl) //message is a proposal message
            {
                const Npl *npl = content->message_as_Npl();
                // execute npl logic here.
                //broadcast message.
            }
            else
            {
                //warn received invalid message from peer.
                LOG_DBG << "Received invalid message type from peer";
                //remove/penalize node who sent the message.
            }
        }
        else
        {
            //warn bad message content.
            LOG_DBG << "Bad message content";
        }
    }
    else
    {
        //warn bad messages from peer.
        LOG_DBG << "Bad message from peer";
    }
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    LOG_DBG << "on_closing peer :" << session->uniqueid_;
}

} // namespace p2p