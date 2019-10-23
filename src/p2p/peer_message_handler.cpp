#include <flatbuffers/flatbuffers.h>
#include <string>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "peer_message_handler.hpp"
#include "message_content_generated.h"
#include "message_container_generated.h"

namespace p2p
{

int validate_and_extract_container(const Container **container_ref, std::string_view container_buf)
{
    //Accessing message buffer
    const uint8_t *container_buf_ptr = reinterpret_cast<const uint8_t *>(container_buf.data());
    size_t container_buf_size = container_buf.length();

    //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
    flatbuffers::Verifier container_verifier(container_buf_ptr, container_buf_size);

    //Verify container message using flatbuffer verifier
    if (!VerifyContainerBuffer(container_verifier))
    {
        LOG_DBG << "Flatbuffer verify: Bad container.";
        return -1;
    }

    //Get message container
    const Container *container = GetContainer(container_buf_ptr);

    //check protocol version of message whether it is greater than minimum supported protocol version.
    const uint16_t version = container->version();
    if (version < util::MIN_PEERMSG_VERSION)
    {
        LOG_DBG << "Recieved message is from unsupported protocol version (" << version << ")";
        return -1;
    }

    //Assign container and content out params.
    *container_ref = container;
    return 0;
}

int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, flatbuffers::uoffset_t content_size)
{
    //Defining Flatbuffer verifier for message content verification.
    //Since content is also serialised by using Flatbuffer we can verify it using Flatbuffer.
    flatbuffers::Verifier content_verifier(content_ptr, content_size);

    //verify content message using flatbuffer verifier.
    if (!VerifyContainerBuffer(content_verifier))
    {
        LOG_DBG << "Flatbuffer verify: Bad content.";
        return -1;
    }

    *content_ref = GetContent(content_ptr);
    return 0;
}

/**
 * Validate the incoming p2p message. Check for message version, timestamp and signature.
 * 
 * @param message binary message content.
 * @param signature binary message signature.
 * @param pubkey binary public key of message originating node.
 * @param timestamp message timestamp.
 * @param version message timestamp.
 * @return whether message is validated or not.
 */
bool validate_content_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp)
{
    //Validation are prioritzed base on expensiveness of validation.
    //i.e - signature validation is done at the end.

    time_t time_now = std::time(nullptr);

    // validate if the message is not from a node of current node's unl list.
    if (!conf::cfg.unl.count(pubkey.data()))
    {
        LOG_DBG << "pubkey verification failed";
        return false;
    }

    //check message timestamp.  < timestamp now - 4* round time.
    /*todo:this might change to check only current stage related. (Base on how consensus algorithm implementation take shape)
    check message stage is for valid stage(node's current consensus stage - 1)
    */
    if (timestamp < (time_now - conf::cfg.roundtime * 4))
    {
        LOG_DBG << "Recieved message from peer is old";
        return false;
    }

    //verify message signature.
    //this should be the last validation since this is bit expensive
    auto signature_verified = crypto::verify(message, signature, pubkey);

    if (signature_verified != 0)
    {
        LOG_DBG << "Signature verification failed";
        return false;
    }

    // After signature is verified, get message hash and see wheteher
    // message is already recieved -> abandon if duplicate.
    auto messageHash = crypto::sha_512_hash(message, "PEERMSG", 7);

    if (recent_peer_msghash.count(messageHash) == 0)
    {
        recent_peer_msghash.try_emplace(std::move(messageHash), timestamp);
    }
    else
    {
        LOG_DBG << "Duplicate message";
        return false;
    }

    return true;
}

proposal create_proposal_from_msg(const Proposal_Message &msg)
{
    proposal p;

    if (msg.pubkey())
        p.pubkey = flatbuff_bytes_to_sv(msg.pubkey());

    p.time = msg.time();
    p.timestamp = msg.timestamp();
    p.stage = msg.stage();

    if (msg.lcl())
        p.lcl = flatbuff_bytes_to_sv(msg.lcl());

    if (msg.users())
        p.users = flatbuf_bytearrayvector_to_vector(msg.users());

    if (msg.raw_inputs())
        p.raw_inputs = flatbuf_pairvector_to_map(msg.raw_inputs());

    if (msg.hash_inputs())
        p.hash_inputs = flatbuf_bytearrayvector_to_vector(msg.hash_inputs());

    if (msg.raw_outputs())
        p.raw_outputs = flatbuf_pairvector_to_map(msg.raw_outputs());

    if (msg.hash_outputs())
        p.hash_outputs = flatbuf_bytearrayvector_to_vector(msg.hash_outputs());

    return p;
}

//private method used to create a proposal message with dummy data.
//Will be similiar to consensus proposal creation in each stage.
const std::string create_message(flatbuffers::FlatBufferBuilder &container_builder)
{
    //todo:get a average propsal message size and allocate builder based on that.
    /*
    * todo: create custom vector allocator for protobuff in order to avoid copying buffer to string.
    * includes overidding socket_session send method to support this as well.
    */
    flatbuffers::FlatBufferBuilder builder(1024);
    time_t timestamp = std::time(nullptr);
    uint8_t stage = 0;

    std::string pubkey = conf::cfg.pubkey;
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pubkey_b = builder.CreateVector((uint8_t *)pubkey.data(), pubkey.size());

    //create dummy propsal message
    flatbuffers::Offset<Proposal_Message> proposal = CreateProposal_Message(builder, pubkey_b, timestamp, stage, timestamp);
    flatbuffers::Offset<Content> message = CreateContent(builder, Message_Proposal_Message, proposal.Union());
    builder.Finish(message); //finished building message content to get serialised content.

    //Get serialized/packed message content pointer and size.
    uint8_t *buf = builder.GetBufferPointer();
    flatbuffers::uoffset_t size = builder.GetSize();

    //Get a binary string_view for the serialised message content.
    const char *content_str = reinterpret_cast<const char *>(buf);
    std::string_view message_content(content_str, size);

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

    //todo: should return buffer_ptr to socket.
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

std::vector<std::string> flatbuf_bytearrayvector_to_vector(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec)
{
    std::vector<std::string> vec;
    for (auto el : *fbvec)
        vec.push_back(std::string(flatbuff_bytes_to_sv(el->array())));
    return vec;
}

std::unordered_map<std::string, std::string> flatbuf_pairvector_to_map(const flatbuffers::Vector<flatbuffers::Offset<StringKeyValuePair>> *fbvec)
{
    std::unordered_map<std::string, std::string> map;
    for (auto el : *fbvec)
        map.emplace(flatbuff_bytes_to_sv(el->key()), flatbuff_bytes_to_sv(el->value()));
    return map;
}

} // namespace p2p