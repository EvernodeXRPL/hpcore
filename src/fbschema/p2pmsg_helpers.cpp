#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../p2p/p2p.hpp"
#include "p2pmsg_container_generated.h"
#include "p2pmsg_content_generated.h"
#include "common_helpers.hpp"
#include "p2pmsg_helpers.hpp"

namespace fbschema::p2pmsg
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
 * @param container_buf The buffer containing the data that should be validated and interpreted
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
        LOG_DBG << "Flatbuffer verify: Bad peer message container.";
        return -1;
    }

    //Get message container
    const Container *container = GetContainer(container_buf_ptr);

    //check protocol version of message whether it is greater than minimum supported protocol version.
    const uint16_t version = container->version();
    if (version < util::MIN_PEERMSG_VERSION)
    {
        LOG_DBG << "Peer message is from unsupported protocol version (" << version << ").";
        return -1;
    }

    //check message timestamp.
    int64_t time_now = util::get_epoch_milliseconds();
    if (container->timestamp() < (time_now - conf::cfg.roundtime * 4))
    {
        LOG_DBG << "Peer message is too old.";
        return -1;
    }

    //Assign container and content out params.
    *container_ref = container;
    return 0;
}

/**
 * Validates the container message signing keys to see if the message is from a trusted source (UNL).
 * @return 0 on successful verification. -1 for failure.
 */
int validate_container_trust(const Container *container)
{
    std::string_view msg_pubkey = flatbuff_bytes_to_sv(container->pubkey());
    std::string_view msg_sig = flatbuff_bytes_to_sv(container->signature());

    if (msg_pubkey.empty() || msg_sig.empty())
    {
        LOG_DBG << "Peer message key pair incomplete. Trust verification failed.";
        return -1;
    }

    //validate if the message is not from a node of current node's unl list.
    if (!conf::cfg.unl.count(std::string(msg_pubkey)))
    {
        LOG_DBG << "Peer message pubkey verification failed. Not in UNL.";
        return -1;
    }

    //verify message signature.
    //this is performed towards end since this is bit expensive
    std::string_view msg_content = flatbuff_bytes_to_sv(container->content());

    if (crypto::verify(msg_content, msg_sig, msg_pubkey) != 0)
    {
        LOG_DBG << "Peer message signature verification failed.";
        return -1;
    }

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
 * Creates a non-unl proposal stuct from the given non-unl proposal message.
 * @param The Flatbuffer non-unl poporal received from the peer.
 * @return A non-unl proposal struct representing the message.
 */
const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, uint64_t timestamp)
{
    p2p::nonunl_proposal nup;
    
    if (msg.usermessages())
        nup.user_messages = flatbuf_usermsgsmap_to_usermsgsmap(msg.usermessages());

    return nup;
}

/**
 * Creates a proposal stuct from the given proposal message.
 * @param The Flatbuffer poporal received from the peer.
 * @return A proposal struct representing the message.
 */
const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, uint64_t timestamp)
{
    p2p::proposal p;

    p.pubkey = flatbuff_bytes_to_sv(pubkey);
    p.timestamp = timestamp;
    p.time = msg.time();
    p.stage = msg.stage();

    if (msg.lcl())
        p.lcl = flatbuff_bytes_to_sv(msg.lcl());

    if (msg.users())
        p.users = flatbuf_bytearrayvector_to_stringlist(msg.users());

    if (msg.hash_inputs())
        p.hash_inputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_inputs());

    if (msg.raw_outputs())
        p.raw_outputs = flatbuf_rawoutputs_to_hashbuffermap(msg.raw_outputs());

    if (msg.hash_outputs())
        p.hash_outputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_outputs());

    return p;
}

//---Message creation helpers---//

void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup)
{
    flatbuffers::FlatBufferBuilder builder(1024);xxxxxxxxxxc

    flatbuffers::Offset<NonUnl_Proposal_Message> nupmsg =
        CreateNonUnl_Proposal_Message(
            builder,
            usermsgsmap_to_flatbuf_usermsgsmap(builder, nup.user_messages));

    flatbuffers::Offset<Content> message = CreateContent(builder, Message_NonUnl_Proposal_Message, nupmsg.Union());
    builder.Finish(message); // Finished building message content to get serialised content.

    // Now that we have built the content message,
    // we need to sign it and place it inside a container message.
    create_containermsg_from_content(container_builder, builder, false);
}

/**
 * Ctreat proposal peer message from the given proposal struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param p The proposal struct to be placed in the container message.
 */
void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p)
{
    // todo:get a average propsal message size and allocate content builder based on that.
    flatbuffers::FlatBufferBuilder builder(1024);

    flatbuffers::Offset<Proposal_Message> proposal =
        CreateProposal_Message(
            builder,
            p.stage,
            p.time,
            sv_to_flatbuff_bytes(builder, p.lcl),
            stringlist_to_flatbuf_bytearrayvector(builder, p.users),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
            hashbuffermap_to_flatbuf_rawoutputs(builder, p.raw_outputs),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs));

    flatbuffers::Offset<Content> message = CreateContent(builder, Message_Proposal_Message, proposal.Union());
    builder.Finish(message); // Finished building message content to get serialised content.

    // Now that we have built the content message,
    // we need to sign it and place it inside a container message.
    create_containermsg_from_content(container_builder, builder, true);
}

/**
 * Creates a Flatbuffer container message from the given Content message.
 * @param container_builder The Flatbuffer builder to which the final container message should be written to.
 * @param content_builder The Flatbuffer builder containing the content message that should be placed
 *                        inside the container message.
 * @param sign Whether to sign the message content.
 */
void create_containermsg_from_content(
    flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, bool sign)
{
    uint8_t *content_buf = content_builder.GetBufferPointer();
    flatbuffers::uoffset_t content_size = content_builder.GetSize();

    // Create container message content from serialised content from previous step.
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> content = container_builder.CreateVector(content_buf, content_size);

    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pubkey_offset = 0;
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> sig_offset = 0;

    if (sign)
    {
        // Sign message content with this node's private key.
        std::string_view content_to_sign(reinterpret_cast<const char *>(content_buf), content_size);

        sig_offset = sv_to_flatbuff_bytes(container_builder, crypto::sign(content_to_sign, conf::cfg.seckey));
        pubkey_offset = sv_to_flatbuff_bytes(container_builder, conf::cfg.pubkey);
    }

    flatbuffers::Offset<Container> container_message = CreateContainer(
        container_builder,
        util::PEERMSG_VERSION,
        util::get_epoch_milliseconds(),
        pubkey_offset,
        sig_offset,
        content);

    // Finish building message container to get serialised message.
    container_builder.Finish(container_message);
}

//---Conversion helpers from flatbuffers data types to std data types---//

const std::unordered_map<std::string, const std::list<usr::user_submitted_message>>
flatbuf_usermsgsmap_to_usermsgsmap(const flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>> *fbvec)
{
    std::unordered_map<std::string, const std::list<usr::user_submitted_message>> map;
    map.reserve(fbvec->size());
    for (const UserSubmittedMessageGroup *group : *fbvec)
    {
        std::list<usr::user_submitted_message> msglist;
        msglist.reserve(group->messages()->size());

        for (auto msg : *group->messages())
        {
            msglist.push_back(usr::user_submitted_message(
                flatbuff_bytes_to_sv(msg->content()),
                flatbuff_bytes_to_sv(msg->signature())
            ));
        }

        map.emplace(flatbuff_bytes_to_sv(group->pubkey()), std::move(msglist));
    }
    return map;
}

/**
 * Returns a hash buffer map from Flatbuffer proposal raw inputs.
 */
const std::unordered_map<std::string, const std::vector<util::hash_buffer>>
flatbuf_rawinputs_to_hashbuffermap(const flatbuffers::Vector<flatbuffers::Offset<RawInputList>> *fbvec)
{
    std::unordered_map<std::string, const std::vector<util::hash_buffer>> map;
    map.reserve(fbvec->size());
    for (const RawInputList *user : *fbvec)
    {
        std::vector<util::hash_buffer> bufvec;
        bufvec.reserve(user->inputs()->size());

        for (auto input : *user->inputs())
        {
            // Create hash_buffer object and manually assign the hash from the input.
            util::hash_buffer buf(flatbuff_bytes_to_sv(input->value())); //input->value() is the raw input.
            buf.hash = flatbuff_bytes_to_sv(input->key());               //input->key() is the hash of the input.

            bufvec.push_back(buf);
        }

        map.emplace(flatbuff_bytes_to_sv(user->pubkey()), std::move(bufvec));
    }
    return map;
}

/**
 * Returns a hash buffer map from Flatbuffer proposal raw outputs.
 */
const std::unordered_map<std::string, util::hash_buffer>
flatbuf_rawoutputs_to_hashbuffermap(const flatbuffers::Vector<flatbuffers::Offset<RawOutput>> *fbvec)
{
    std::unordered_map<std::string, util::hash_buffer> map;
    map.reserve(fbvec->size());
    for (const RawOutput *user : *fbvec)
    {
        // Create hash_buffer object and manually assign the hash from the output.
        util::hash_buffer buf(flatbuff_bytes_to_sv(user->output()->value())); //output->value() is the raw output.
        buf.hash = flatbuff_bytes_to_sv(user->output()->key());               //output->key() is the hash of the output.

        map.emplace(flatbuff_bytes_to_sv(user->pubkey()), std::move(buf));
    }
    return map;
}

//---Conversion helpers from std data types to flatbuffers data types---//
//---These are used in constructing Flatbuffer messages using builders---//

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>>>
usermsgsmap_to_flatbuf_usermsgsmap(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::list<usr::user_submitted_message>> &map)
{
    std::vector<flatbuffers::Offset<UserSubmittedMessageGroup>> fbvec;
    fbvec.reserve(map.size());
    for (auto const &[pubkey, msglist] : map)
    {
        std::vector<flatbuffers::Offset<UserSubmittedMessage>> fbmsgsvec;
        for (const usr::user_submitted_message &msg : msglist)
        {
            fbmsgsvec.push_back(UserSubmittedMessage(
                builder,
                sv_to_flatbuff_bytes(builder, msg.content),
                sv_to_flatbuff_bytes(builder, msg.sig)));
        }

        fbvec.push_back(CreateUserSubmittedMessageGroup(
            builder,
            sv_to_flatbuff_bytes(builder, pubkey),
            builder.CreateVector(fbmsgsvec)));
    }
    return builder.CreateVector(fbvec);
}


/**
 * Returns Flatbuffer vector of RawInputs from a given map of hash buffer lists.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<RawInputList>>>
hashbuffermap_to_flatbuf_rawinputs(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::vector<util::hash_buffer>> &map)
{
    std::vector<flatbuffers::Offset<RawInputList>> fbvec;
    fbvec.reserve(map.size());
    for (auto const &[pubkey, bufvec] : map)
    {
        std::vector<flatbuffers::Offset<BytesKeyValuePair>> fbinputsvec;
        for (const util::hash_buffer &buf : bufvec)
        {
            fbinputsvec.push_back(CreateBytesKeyValuePair(
                builder,
                sv_to_flatbuff_bytes(builder, buf.hash),
                sv_to_flatbuff_bytes(builder, buf.buffer)));
        }

        fbvec.push_back(CreateRawInputList(
            builder,
            sv_to_flatbuff_bytes(builder, pubkey),
            builder.CreateVector(fbinputsvec)));
    }
    return builder.CreateVector(fbvec);
}

/**
 * Returns Flatbuffer vector of RawOutputs from a given map of hash buffers.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<RawOutput>>>
hashbuffermap_to_flatbuf_rawoutputs(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, util::hash_buffer> &map)
{
    std::vector<flatbuffers::Offset<RawOutput>> fbvec;
    fbvec.reserve(map.size());
    for (auto const &[pubkey, buf] : map)
    {
        fbvec.push_back(CreateRawOutput(
            builder,
            sv_to_flatbuff_bytes(builder, pubkey),
            CreateBytesKeyValuePair(
                builder,
                sv_to_flatbuff_bytes(builder, buf.hash),
                sv_to_flatbuff_bytes(builder, buf.buffer))));
    }
    return builder.CreateVector(fbvec);
}

} // namespace fbschema::p2pmsg