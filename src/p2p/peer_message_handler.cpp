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

/**
 * This section contains Flatbuffer message reading/writing helpers.
 * These helpers are mainly used by peer_session_handler.
 * 
 * All Flatbuffer peer messages are 'Container' messages. 'Container' message is a bucket
 * which some common headers (version, singature etc..) and the message 'Content' (Proposal, NPL etc..).
 * 
 * Therefore, when constructing peer messages, we have to first construct 'Content' message and then
 * place the 'Content' inside a 'Conatiner. 'Content' and 'Container' messages are constructed using
 * Flatbuffer builders.
 * 
 * Reading is also 2 steps because of this. We have first interprit the 'Container' message from the
 * received data and then interprit the 'Content' portion of it separately to read the actual content.
 */

//---Message validation and reading helpers---/

/**
 * Verifies Conatiner message structure and outputs faltbuffer Container pointer to access the given buffer.
 * 
 * @param container_ref A pointer reference to assign the pointer to the Container object.
 * @param container_bud The buffer containing the data that should validated and interpreted
 *                      via the container pointer.
 * @return 0 on successful verification. -1 for failure.
 */
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

/**
 * Verifies the Content message structure and outputs faltbuffer Content pointer to access the given buffer.
 * 
 * @param content_ref A pointer reference to assign the pointer to the Content object.
 * @param content_ptr Pointer to the the buffer containing the data that should validated and interpreted
 *                      via the container pointer.
 * @param content_size Data buffer size.
 * @return 0 on successful verification. -1 for failure.
 */
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
 * Validate the incoming p2p message content on several criteria.
 * 
 * @param message Message content data buffer.
 * @param signature Binary message signature.
 * @param pubkey Binary public key of message originating node.
 * @param timestamp Message timestamp.
 * @param version Message protocol version.
 * @return 0 on successful validation. -1 for failure.
 */
int validate_content_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp)
{
    //Validation are prioritzed base on expensiveness of validation.
    //i.e - signature validation is done at the end.

    time_t time_now = std::time(nullptr);

    // validate if the message is not from a node of current node's unl list.
    if (!conf::cfg.unl.count(pubkey.data()))
    {
        LOG_DBG << "pubkey verification failed";
        return -1;
    }

    //check message timestamp.  < timestamp now - 4* round time.
    /*todo:this might change to check only current stage related. (Base on how consensus algorithm implementation take shape)
    check message stage is for valid stage(node's current consensus stage - 1)
    */
    if (timestamp < (time_now - conf::cfg.roundtime * 4))
    {
        LOG_DBG << "Recieved message from peer is old";
        return -1;
    }

    //verify message signature.
    //this should be the last validation since this is bit expensive
    auto signature_verified = crypto::verify(message, signature, pubkey);

    if (signature_verified != 0)
    {
        LOG_DBG << "Signature verification failed";
        return -1;
    }

    // After signature is verified, get message hash and see wheteher
    // message is already recieved -> abandon if duplicate.
    // auto messageHash = crypto::sha_512_hash(message, "PEERMSG", 7);

    // if (recent_peer_msghash.count(messageHash) == 0)
    // {
    //     recent_peer_msghash.try_emplace(std::move(messageHash), timestamp);
    // }
    // else
    // {
    //     LOG_DBG << "Duplicate message";
    //     return -1;
    // }

    return 0;
}

/**
 * Creates a proposal stuct from the given proposal message.
 * @param The Flatbuffer poporal received from the peer.
 * @return A proposal struct representing the message.
 */
const proposal create_proposal_from_msg(const Proposal_Message &msg)
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
        p.users = flatbuf_bytearrayvector_to_stringlist(msg.users());

    if (msg.raw_inputs())
        p.raw_inputs = flatbuf_pairvector_to_stringmap(msg.raw_inputs());

    if (msg.hash_inputs())
        p.hash_inputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_inputs());

    if (msg.raw_outputs())
        p.raw_outputs = flatbuf_pairvector_to_stringmap(msg.raw_outputs());

    if (msg.hash_outputs())
        p.hash_outputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_outputs());

    return p;
}

//---Message creation helpers---//

/**
 * Ctreat proposal peer message from the given proposal struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param p The proposal struct to be placed in the container message.
 */
void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const proposal &p)
{
    // todo:get a average propsal message size and allocate content builder based on that.
    flatbuffers::FlatBufferBuilder builder(1024);

    // Create dummy propsal message
    flatbuffers::Offset<Proposal_Message> proposal =
        CreateProposal_Message(
            builder,
            sv_to_flatbuff_bytes(builder, conf::cfg.pubkey),
            p.timestamp,
            p.stage,
            p.time,
            sv_to_flatbuff_bytes(builder, p.lcl),
            stringlist_to_flatbuf_bytearrayvector(builder, p.users),
            stringmap_to_flatbuf_bytepairvector(builder, p.raw_inputs),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
            stringmap_to_flatbuf_bytepairvector(builder, p.raw_outputs),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs));

    flatbuffers::Offset<Content> message = CreateContent(builder, Message_Proposal_Message, proposal.Union());
    builder.Finish(message); // Finished building message content to get serialised content.

    // Now that we have built the content message,
    // we need to sign it and place it inside a container message.
    create_containermsg_from_content(container_builder, builder);
}

/**
 * Creates a Flatbuffer container message from the given Content message.
 * @param container_builder The Flatbuffer builder to which the final container message should be written to.
 * @param content_builder The Flatbuffer builder containing the content message that should be placed
 *                        inside the container message.
 */
void create_containermsg_from_content(
    flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder)
{
    uint8_t *content_buf = content_builder.GetBufferPointer();
    flatbuffers::uoffset_t content_size = content_builder.GetSize();

    // Create container message content from serialised content from previous step.
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> content = container_builder.CreateVector(content_buf, content_size);

    // Sign message content with this node's private key.
    std::string_view content_to_sign(reinterpret_cast<const char *>(content_buf), content_size);
    std::string sig = crypto::sign(content_to_sign, conf::cfg.seckey);

    flatbuffers::Offset<Container> container_message = CreateContainer(
        container_builder,
        util::PEERMSG_VERSION,
        sv_to_flatbuff_bytes(container_builder, sig), //signature field
        content);

    // Finish building message container to get serialised message.
    container_builder.Finish(container_message);
}

//---Conversion helpers from flatbuffers data types to std data types---//

/**
 * Returns string_view from flat buffer data pointer and length.
 */
std::string_view flatbuff_bytes_to_sv(const uint8_t *data, flatbuffers::uoffset_t length)
{
    const char *signature_content_str = reinterpret_cast<const char *>(data);
    return std::string_view(signature_content_str, length);
}

/**
 * Returns return string_view from Flat Buffer vector of bytes.
 */
std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer)
{
    return flatbuff_bytes_to_sv(buffer->Data(), buffer->size());
}

/**
 * Returns set from Flatbuffer vector of ByteArrays.
 */
const std::unordered_set<std::string> flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec)
{
    std::unordered_set<std::string> set;
    set.reserve(fbvec->size());
    for (auto el : *fbvec)
        set.emplace(std::string(flatbuff_bytes_to_sv(el->array())));
    return set;
}

/**
 * Returns a map from Flatbuffer vector of key value pairs.
 */
const std::unordered_map<std::string, const std::string>
flatbuf_pairvector_to_stringmap(const flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>> *fbvec)
{
    std::unordered_map<std::string, const std::string> map;
    map.reserve(fbvec->size());
    for (auto el : *fbvec)
        map.emplace(flatbuff_bytes_to_sv(el->key()), flatbuff_bytes_to_sv(el->value()));
    return map;
}

//---Conversion helpers from std data types to flatbuffers data types---//
//---These are used in constructing Flatbuffer messages using builders---//

/**
 * Returns Flatbuffer bytes vector from string_view.
 */
const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
sv_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv)
{
    return builder.CreateVector(reinterpret_cast<const uint8_t *>(sv.data()), sv.size());
}

/**
 * Returns Flatbuffer vector of ByteArrays from given set of strings.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::unordered_set<std::string> &set)
{
    std::vector<flatbuffers::Offset<ByteArray>> fbvec;
    fbvec.reserve(set.size());
    for (std::string_view str : set)
        fbvec.push_back(CreateByteArray(builder, sv_to_flatbuff_bytes(builder, str)));
    return builder.CreateVector(fbvec);
}

/**
 * Returns Flatbuffer vector of key value pairs from given map.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>>>
stringmap_to_flatbuf_bytepairvector(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::string> &map)
{
    std::vector<flatbuffers::Offset<BytesKeyValuePair>> fbvec;
    fbvec.reserve(map.size());
    for (auto const &[key, value] : map)
    {
        fbvec.push_back(CreateBytesKeyValuePair(
            builder,
            sv_to_flatbuff_bytes(builder, key),
            sv_to_flatbuff_bytes(builder, value)));
    }
    return builder.CreateVector(fbvec);
}

} // namespace p2p