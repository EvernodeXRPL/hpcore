#include "../../pchheader.hpp"
#include "../../conf.hpp"
#include "../../crypto.hpp"
#include "../../util.hpp"
#include "../../hplog.hpp"
#include "../../hpfs/h32.hpp"
#include "../../hpfs/hpfs.hpp"
#include "p2pmsg_container_generated.h"
#include "p2pmsg_content_generated.h"
#include "common_helpers.hpp"
#include "p2pmsg_helpers.hpp"

namespace msg::fbuf::p2pmsg
{

    // Length of a peer connection challange.
    constexpr size_t PEERCHALLENGE_LEN = 16;

    // Max size of messages which are subjected to time (too old) check.
    constexpr size_t MAX_SIZE_FOR_TIME_CHECK = 1 * 1024 * 1024; // 1 MB

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

    //---Message validation helpers---/

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
        const size_t container_buf_size = container_buf.length();

        //Defining Flatbuffer verifier (default max depth = 64, max_tables = 1000000,)
        flatbuffers::Verifier container_verifier(container_buf_ptr, container_buf_size);

        //Verify container message using flatbuffer verifier
        if (!VerifyContainerBuffer(container_verifier))
        {
            LOG_DEBUG << "Flatbuffer verify: Bad peer message container.";
            return -1;
        }

        //Get message container
        const Container *container = GetContainer(container_buf_ptr);

        //check protocol version of message whether it is greater than minimum supported protocol version.
        const uint16_t version = container->version();
        if (version < util::MIN_PEERMSG_VERSION)
        {
            LOG_DEBUG << "Peer message is from unsupported protocol version (" << version << ").";
            return -1;
        }

        //check message timestamp (ignore this for large messages).
        if (container_buf_size <= MAX_SIZE_FOR_TIME_CHECK)
        {
            const int64_t time_now = util::get_epoch_milliseconds();
            if (container->timestamp() < (time_now - conf::cfg.roundtime * 4))
            {
                LOG_DEBUG << "Peer message is too old.";
                return -1;
            }
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
            LOG_DEBUG << "Peer message key pair incomplete. Trust verification failed.";
            return -1;
        }

        //validate if the message is not from a node of current node's unl list.
        if (!conf::cfg.unl.count(std::string(msg_pubkey)))
        {
            LOG_DEBUG << "Peer message pubkey verification failed. Not in UNL.";
            return -1;
        }

        //verify message signature.
        //this is performed towards end since this is bit expensive
        std::string_view msg_content = flatbuff_bytes_to_sv(container->content());

        if (crypto::verify(msg_content, msg_sig, msg_pubkey) != 0)
        {
            LOG_DEBUG << "Peer message signature verification failed.";
            return -1;
        }

        return 0;
    }

    /**
 * Verifies the Content message structure and outputs faltbuffer Content pointer to access the given buffer.
 * 
 * @param content_ref A pointer reference to assign the pointer to the Content object.
 * @param content_ptr Pointer to the buffer containing the data that should validated and interpreted
 *                      via the container pointer.
 * @param content_size Data buffer size.
 * @return 0 on successful verification. -1 for failure.
 */
    int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, const flatbuffers::uoffset_t content_size)
    {
        //Defining Flatbuffer verifier for message content verification.
        //Since content is also serialised by using Flatbuffer we can verify it using Flatbuffer.
        flatbuffers::Verifier content_verifier(content_ptr, content_size);

        //verify content message using flatbuffer verifier.
        if (!VerifyContainerBuffer(content_verifier))
        {
            LOG_DEBUG << "Flatbuffer verify: Bad content.";
            return -1;
        }

        *content_ref = GetContent(content_ptr);
        return 0;
    }

    //---Message reading helpers---/

    /**
 * Returns challenge from the peer challenge message.
 * @param The Flatbuffer peer challenge message received from the peer.
 * @return binary challenge.
 */
    const std::string_view get_peer_challenge_from_msg(const Peer_Challenge_Message &msg)
    {
        return flatbuff_bytes_to_sv(msg.challenge());
    }

    /**
 * Creates a peer challenge response struct from the given peer challenge response message.
 * @param The Flatbuffer peer challenge response message received from the peer.
 * @return A peer challenge response struct representing the message.
 */
    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const Peer_Challenge_Response_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey)
    {
        p2p::peer_challenge_response pchalresp;

        pchalresp.challenge = flatbuff_bytes_to_sv(msg.challenge());
        pchalresp.signature = flatbuff_bytes_to_sv(msg.sig());
        pchalresp.pubkey = flatbuff_bytes_to_sv(pubkey);

        return pchalresp;
    }

    /**
 * Creates a non-unl proposal stuct from the given non-unl proposal message.
 * @param The Flatbuffer non-unl poporal received from the peer.
 * @return A non-unl proposal struct representing the message.
 */
    const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, const uint64_t timestamp)
    {
        p2p::nonunl_proposal nup;

        if (msg.user_inputs())
            nup.user_inputs = flatbuf_user_input_group_to_user_input_map(msg.user_inputs());

        return nup;
    }

    /**
 * Creates a history response stuct from the given histrory response message.
 * @param msg Flatbuffer History response message received from the peer.
 * @return A History response struct representing the message.
 */
    const p2p::history_response create_history_response_from_msg(const History_Response_Message &msg)
    {
        p2p::history_response hr;

        if (msg.requester_lcl())
            hr.requester_lcl = flatbuff_bytes_to_sv(msg.requester_lcl());

        if (msg.hist_ledger_blocks())
            hr.hist_ledger_blocks = flatbuf_historyledgermap_to_historyledgermap(msg.hist_ledger_blocks());

        if (msg.error())
            hr.error = (p2p::LEDGER_RESPONSE_ERROR)msg.error();

        return hr;
    }

    /**
 * Creates a proposal stuct from the given proposal message.
 * @param The Flatbuffer poposal received from the peer.
 * @return A proposal struct representing the message.
 */
    const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, const uint64_t timestamp, const flatbuffers::Vector<uint8_t> *lcl)
    {
        p2p::proposal p;

        p.pubkey = flatbuff_bytes_to_sv(pubkey);
        p.sent_timestamp = timestamp;
        p.time = msg.time();
        p.stage = msg.stage();
        p.lcl = flatbuff_bytes_to_sv(lcl);
        p.state = flatbuff_bytes_to_sv(msg.state());

        if (msg.users())
            p.users = flatbuf_bytearrayvector_to_stringlist(msg.users());

        if (msg.hash_inputs())
            p.hash_inputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_inputs());

        if (msg.hash_outputs())
            p.hash_outputs = flatbuf_bytearrayvector_to_stringlist(msg.hash_outputs());

        return p;
    }

    /**
 * Creates a history request struct from the given history request message.
 * @param msg Flatbuffer History request message received from the peer.
 * @return A History request struct representing the message.
 */
    const p2p::history_request create_history_request_from_msg(const History_Request_Message &msg)
    {
        p2p::history_request hr;

        if (msg.minimum_lcl())
            hr.minimum_lcl = flatbuff_bytes_to_sv(msg.minimum_lcl());

        if (msg.required_lcl())
            hr.required_lcl = flatbuff_bytes_to_sv(msg.required_lcl());

        return hr;
    }

    /**
 * Creates a state request struct from the given state request message.
 * @param msg Flatbuffer State request message received from the peer.
 * @return A State request struct representing the message.
 */
    const p2p::state_request create_state_request_from_msg(const State_Request_Message &msg)
    {
        p2p::state_request sr;

        sr.block_id = msg.block_id();
        sr.is_file = msg.is_file();
        sr.parent_path = flatbuff_str_to_sv(msg.parent_path());
        sr.expected_hash = flatbuff_bytes_to_hash(msg.expected_hash());

        return sr;
    }

    /**
 * Creates a peer property list from the given peer list response message.
 * @param msg Flatbuffer Peer List response message received from the peer.
 * @return A Peer list representing the message.
 */
    const std::vector<conf::peer_properties> create_peer_list_response_from_msg(const Peer_List_Response_Message &msg)
    {
        return flatbuf_peer_propertieslist_to_peer_propertiesvector(msg.peer_list());
    }

    //---Message creation helpers---//

    /**
 * Create peer challenge message from the given challenge.
 * @param container_builder Flatbuffer builder for the container message.
 * @param challenge Challenge message needed to convert to flatbuffer message.
 */
    void create_msg_from_peer_challenge(flatbuffers::FlatBufferBuilder &container_builder, std::string &challenge)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        // We calculate the peer challenge to be a random string.
        // Use libsodium to generate the random challenge bytes.
        challenge.resize(PEERCHALLENGE_LEN);
        randombytes_buf(challenge.data(), PEERCHALLENGE_LEN);

        const flatbuffers::Offset<Peer_Challenge_Message> peer_challenge_msg =
            CreatePeer_Challenge_Message(
                builder,
                sv_to_flatbuff_bytes(builder, challenge));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Peer_Challenge_Message, peer_challenge_msg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message
        create_containermsg_from_content(container_builder, builder, {}, false);
    }

    /**
 * Create peer challenge response message from the given challenge.
 * @param container_builder Flatbuffer builder for the container message.
 * @param challenge Message which need to be signed and placed in the container message.
 */
    void create_peer_challenge_response_from_challenge(flatbuffers::FlatBufferBuilder &container_builder, const std::string &challenge)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Peer_Challenge_Response_Message> challenge_resp_msg =
            CreatePeer_Challenge_Response_Message(
                builder,
                sv_to_flatbuff_bytes(builder, challenge),
                sv_to_flatbuff_bytes(builder, crypto::sign(challenge, conf::cfg.seckey)));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Peer_Challenge_Response_Message, challenge_resp_msg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, {}, true);
    }

    void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<NonUnl_Proposal_Message> nupmsg =
            CreateNonUnl_Proposal_Message(
                builder,
                user_input_map_to_flatbuf_user_input_group(builder, nup.user_inputs));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_NonUnl_Proposal_Message, nupmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, {}, false);
    }

    /**
 * Create proposal peer message from the given proposal struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param p The proposal struct to be placed in the container message.
 */
    void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p)
    {
        // todo:get a average propsal message size and allocate content builder based on that.
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Proposal_Message> proposal =
            CreateProposal_Message(
                builder,
                p.stage,
                p.time,
                stringlist_to_flatbuf_bytearrayvector(builder, p.users),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs),
                hash_to_flatbuff_bytes(builder, p.state));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Proposal_Message, proposal.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, p.lcl, true);
    }

    /**
 * Ctreat npl message from the given npl output srtuct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param msg The message to be sent as NPL message.
 * @param lcl Lcl value to be passed in the container message.
 */
    void create_msg_from_npl_output(flatbuffers::FlatBufferBuilder &container_builder, const std::string_view &msg, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Npl_Message> npl =
            CreateNpl_Message(
                builder,
                sv_to_flatbuff_bytes(builder, msg));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Npl_Message, npl.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
 * Create history request message from the given history request struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param hr The History request struct to be placed in the container message.
 */
    void create_msg_from_history_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_request &hr)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        flatbuffers::Offset<History_Request_Message> hrmsg =
            CreateHistory_Request_Message(
                builder,
                sv_to_flatbuff_bytes(builder, hr.minimum_lcl),
                sv_to_flatbuff_bytes(builder, hr.required_lcl));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_History_Request_Message, hrmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, {}, false);
    }

    /**
 * Create history response message from the given history response struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param hr The History response struct to be placed in the container message.
 */
    void create_msg_from_history_response(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_response &hr)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        flatbuffers::Offset<History_Response_Message> hrmsg =
            CreateHistory_Response_Message(
                builder,
                sv_to_flatbuff_bytes(builder, hr.requester_lcl),
                historyledgermap_to_flatbuf_historyledgermap(builder, hr.hist_ledger_blocks),
                (Ledger_Response_Error)hr.error);

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_History_Response_Message, hrmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, {}, false);
    }

    /**
 * Create state request message from the given state request struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param sr The state request struct to be placed in the container message.
 */
    void create_msg_from_state_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::state_request &hr, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        flatbuffers::Offset<State_Request_Message> srmsg =
            CreateState_Request_Message(
                builder,
                sv_to_flatbuff_str(builder, hr.parent_path),
                hr.is_file,
                hr.block_id,
                hash_to_flatbuff_bytes(builder, hr.expected_hash));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_State_Request_Message, srmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
 * Create content response message from the given content response.
 * @param container_builder Flatbuffer builder for the container message.
 * @param path The path of the directory.
 * @param hash_nodes File or directory entries with hashes in the given parent path.
 * @param expected_hash The exptected hash of the requested path.
 * @param lcl Lcl to be include in the container msg.
 */
    void create_msg_from_fsentry_response(
        flatbuffers::FlatBufferBuilder &container_builder, const std::string_view path,
        std::vector<hpfs::child_hash_node> &hash_nodes, hpfs::h32 expected_hash, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Fs_Entry_Response> resp =
            CreateFs_Entry_Response(
                builder,
                statefshashentry_to_flatbuff_statefshashentry(builder, hash_nodes));

        const flatbuffers::Offset<State_Response_Message> st_resp = CreateState_Response_Message(
            builder, State_Response_Fs_Entry_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, expected_hash),
            sv_to_flatbuff_str(builder, path));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_State_Response_Message, st_resp.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
 * Create content response message from the given content response.
 * @param container_builder Flatbuffer builder for the container message.
 * @param path The path of the directory.
 * @param hashmap Hashmap of the file
 * @param lcl Lcl to be include in the container msg.
 */
    void create_msg_from_filehashmap_response(
        flatbuffers::FlatBufferBuilder &container_builder, std::string_view path,
        std::vector<hpfs::h32> &hashmap, std::size_t file_length, hpfs::h32 expected_hash, std::string_view lcl)
    {
        // todo:get a average propsal message size and allocate content builder based on that.
        flatbuffers::FlatBufferBuilder builder(1024);

        std::string_view hashmap_sv(reinterpret_cast<const char *>(hashmap.data()), hashmap.size() * sizeof(hpfs::h32));

        const flatbuffers::Offset<File_HashMap_Response> resp =
            CreateFile_HashMap_Response(
                builder,
                file_length,
                sv_to_flatbuff_bytes(builder, hashmap_sv));

        const flatbuffers::Offset<State_Response_Message> st_resp = CreateState_Response_Message(
            builder,
            State_Response_File_HashMap_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, expected_hash),
            sv_to_flatbuff_str(builder, path));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_State_Response_Message, st_resp.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
 * Create content response message from the given content response.
 * @param container_builder Flatbuffer builder for the container message.
 * @param block_resp Block response struct to place in the message
 * @param lcl Lcl to be include in the container message.
 */
    void create_msg_from_block_response(flatbuffers::FlatBufferBuilder &container_builder, p2p::block_response &block_resp, std::string_view lcl)
    {
        // todo:get a average propsal message size and allocate content builder based on that.
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Block_Response> resp =
            CreateBlock_Response(
                builder,
                block_resp.block_id,
                sv_to_flatbuff_bytes(builder, block_resp.data));

        const flatbuffers::Offset<State_Response_Message> st_resp = CreateState_Response_Message(
            builder,
            State_Response_Block_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, block_resp.hash),
            sv_to_flatbuff_str(builder, block_resp.path));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_State_Response_Message, st_resp.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
     * Create connected status announcement message.
     * @param container_builder Flatbuffer builder for the container message.
     * @param need_consensus_msg_forwarding True if number of connections are below threshold and false otherwise.
     * @param lcl Lcl value to be passed in the container message.
     */
    void create_msg_from_peer_requirement_announcement(flatbuffers::FlatBufferBuilder &container_builder, const bool need_consensus_msg_forwarding, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Peer_Requirement_Announcement_Message> announcement =
            CreatePeer_Requirement_Announcement_Message(
                builder,
                need_consensus_msg_forwarding);

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Peer_Requirement_Announcement_Message, announcement.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
     * Create available capacity announcement message.
     * @param container_builder Flatbuffer builder for the container message.
     * @param available_capacity Number of incoming connection slots available, -1 means there's no limitation for connections.
     * @param timestamp Announced timestamp.
     * @param lcl Lcl value to be passed in the container message.
     */
    void create_msg_from_available_capacity_announcement(flatbuffers::FlatBufferBuilder &container_builder, const int16_t &available_capacity, const uint64_t &timestamp, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Available_Capacity_Announcement_Message> announcement =
            CreateAvailable_Capacity_Announcement_Message(
                builder,
                available_capacity,
                timestamp);

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Available_Capacity_Announcement_Message, announcement.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
     * Create peer list request message.
     * @param container_builder Flatbuffer builder for the container message.
     * @param lcl Lcl value to be passed in the container message.
     */
    void create_msg_from_peer_list_request(flatbuffers::FlatBufferBuilder &container_builder, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Peer_List_Request_Message> request =
            CreatePeer_List_Request_Message(
                builder);

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Peer_List_Request_Message, request.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
     * Create peer list response message.
     * @param container_builder Flatbuffer builder for the container message.
     * @param peers Peer list to be sent to another peer.
     * @param skipping_peer Peer that does not need to be sent.
     * @param lcl Lcl value to be passed in the container message.
     */
    void create_msg_from_peer_list_response(flatbuffers::FlatBufferBuilder &container_builder, const std::vector<conf::peer_properties> &peers, const std::optional<conf::ip_port_prop> &skipping_ip_port, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Peer_List_Response_Message> response =
            CreatePeer_List_Response_Message(
                builder,
                peer_propertiesvector_to_flatbuf_peer_propertieslist(builder, peers, skipping_ip_port));

        const flatbuffers::Offset<Content> message = CreateContent(builder, Message_Peer_List_Response_Message, response.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
 * Creates a Flatbuffer container message from the given Content message.
 * @param container_builder The Flatbuffer builder to which the final container message should be written to.
 * @param content_builder The Flatbuffer builder containing the content message that should be placed
 *                        inside the container message.
 * @param sign Whether to sign the message content.
 */
    void create_containermsg_from_content(
        flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, std::string_view lcl, const bool sign)
    {
        const uint8_t *content_buf = content_builder.GetBufferPointer();
        const flatbuffers::uoffset_t content_size = content_builder.GetSize();

        // Create container message content from serialised content from previous step.
        const flatbuffers::Offset<flatbuffers::Vector<uint8_t>> content = container_builder.CreateVector(content_buf, content_size);

        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pubkey_offset = 0;
        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> sig_offset = 0;

        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> lcl_offset = 0;

        if (sign)
        {
            // Sign message content with this node's private key.
            std::string_view content_to_sign(reinterpret_cast<const char *>(content_buf), content_size);

            sig_offset = sv_to_flatbuff_bytes(container_builder, crypto::sign(content_to_sign, conf::cfg.seckey));
            pubkey_offset = sv_to_flatbuff_bytes(container_builder, conf::cfg.pubkey);
        }

        if (!lcl.empty())
            lcl_offset = sv_to_flatbuff_bytes(container_builder, lcl);

        const flatbuffers::Offset<Container> container_message = CreateContainer(
            container_builder,
            util::PEERMSG_VERSION,
            util::get_epoch_milliseconds(),
            pubkey_offset,
            lcl_offset,
            sig_offset,
            content);

        // Finish building message container to get serialised message.
        container_builder.Finish(container_message);
    }

    //---Conversion helpers from flatbuffers data types to std data types---//

    const std::unordered_map<std::string, std::list<usr::user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec)
    {
        std::unordered_map<std::string, std::list<usr::user_input>> map;
        map.reserve(fbvec->size());
        for (const UserInputGroup *group : *fbvec)
        {
            std::list<usr::user_input> user_inputs_list;

            for (const auto msg : *group->messages())
            {
                user_inputs_list.push_back(usr::user_input(
                    flatbuff_bytes_to_sv(msg->input_container()),
                    flatbuff_bytes_to_sv(msg->signature()),
                    static_cast<util::PROTOCOL>(msg->protocol())));
            }

            map.emplace(flatbuff_bytes_to_sv(group->pubkey()), std::move(user_inputs_list));
        }
        return map;
    }

    //---Conversion helpers from std data types to flatbuffers data types---//
    //---These are used in constructing Flatbuffer messages using builders---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::list<usr::user_input>> &map)
    {
        std::vector<flatbuffers::Offset<UserInputGroup>> fbvec;
        fbvec.reserve(map.size());
        for (const auto &[pubkey, msglist] : map)
        {
            std::vector<flatbuffers::Offset<UserInput>> fbmsgsvec;
            for (const usr::user_input &msg : msglist)
            {
                fbmsgsvec.push_back(CreateUserInput(
                    builder,
                    sv_to_flatbuff_bytes(builder, msg.input_container),
                    sv_to_flatbuff_bytes(builder, msg.sig),
                    static_cast<uint8_t>(msg.protocol)));
            }

            fbvec.push_back(CreateUserInputGroup(
                builder,
                sv_to_flatbuff_bytes(builder, pubkey),
                builder.CreateVector(fbmsgsvec)));
        }
        return builder.CreateVector(fbvec);
    }

    const std::map<uint64_t, const p2p::history_ledger_block>
    flatbuf_historyledgermap_to_historyledgermap(const flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerBlockPair>> *fbvec)
    {
        std::map<uint64_t, const p2p::history_ledger_block> map;

        for (const HistoryLedgerBlockPair *pair : *fbvec)
        {
            std::list<usr::user_input> msglist;

            p2p::history_ledger_block ledger;

            ledger.lcl = flatbuff_bytes_to_sv(pair->ledger()->lcl());
            auto raw = pair->ledger()->block_buffer();
            ledger.block_buffer = std::vector<uint8_t>(raw->begin(), raw->end());

            map.emplace(pair->seq_no(), std::move(ledger));
        }
        return map;
    }

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerBlockPair>>>
    historyledgermap_to_flatbuf_historyledgermap(flatbuffers::FlatBufferBuilder &builder, const std::map<uint64_t, const p2p::history_ledger_block> &map)
    {
        std::vector<flatbuffers::Offset<HistoryLedgerBlockPair>> fbvec;
        fbvec.reserve(map.size());
        for (auto const &[seq_no, ledger] : map)
        {
            flatbuffers::Offset<HistoryLedgerBlock> history_ledger = CreateHistoryLedgerBlock(
                builder,
                sv_to_flatbuff_bytes(builder, ledger.lcl),
                builder.CreateVector(ledger.block_buffer));

            fbvec.push_back(CreateHistoryLedgerBlockPair(
                builder,
                seq_no,
                history_ledger));
        }
        return builder.CreateVector(fbvec);
    }

    void flatbuf_statefshashentry_to_statefshashentry(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries, const flatbuffers::Vector<flatbuffers::Offset<State_FS_Hash_Entry>> *fhashes)
    {
        for (const State_FS_Hash_Entry *f_hash : *fhashes)
        {
            p2p::state_fs_hash_entry entry;
            entry.name = flatbuff_str_to_sv(f_hash->name());
            entry.is_file = f_hash->is_file();
            entry.hash = flatbuff_bytes_to_hash(f_hash->hash());

            fs_entries.emplace(entry.name, std::move(entry));
        }
    }

    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<State_FS_Hash_Entry>>>
    statefshashentry_to_flatbuff_statefshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes)
    {
        std::vector<flatbuffers::Offset<State_FS_Hash_Entry>> fbvec;
        fbvec.reserve(hash_nodes.size());
        for (auto const &hash_node : hash_nodes)
        {
            flatbuffers::Offset<State_FS_Hash_Entry> state_fs_entry = CreateState_FS_Hash_Entry(
                builder,
                sv_to_flatbuff_str(builder, hash_node.name),
                hash_node.is_file,
                hash_to_flatbuff_bytes(builder, hash_node.hash));

            fbvec.push_back(state_fs_entry);
        }
        return builder.CreateVector(fbvec);
    }

    /**
 * Create peer list message from the given vector of peer properties structs.
 * @param container_builder Flatbuffer builder for the container message.
 * @param peers The Vector of peer properties to be placed in the container message.
 * @param skipping_peer Peer that does not need to be sent.
 */
    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<Peer_Properties>>>
    peer_propertiesvector_to_flatbuf_peer_propertieslist(flatbuffers::FlatBufferBuilder &builder, const std::vector<conf::peer_properties> &peers, const std::optional<conf::ip_port_prop> &skipping_ip_port)
    {
        std::vector<flatbuffers::Offset<Peer_Properties>> fbvec;
        fbvec.reserve(peers.size());
        for (auto peer : peers)
        {
            // Skipping the requestedc peer from the peer list response.
            if (!skipping_ip_port.has_value() || peer.ip_port != skipping_ip_port.value())
                fbvec.push_back(CreatePeer_Properties(
                    builder,
                    sv_to_flatbuff_str(builder, peer.ip_port.host_address),
                    peer.ip_port.port,
                    peer.available_capacity,
                    peer.timestamp));
        }
        return builder.CreateVector(fbvec);
    }

    /**
 * Create vector of peer properties structs from the given peer list message.
 * @param fbvec The peer list message to be convert to a list of peer properties structs.
 */
    const std::vector<conf::peer_properties>
    flatbuf_peer_propertieslist_to_peer_propertiesvector(const flatbuffers::Vector<flatbuffers::Offset<Peer_Properties>> *fbvec)
    {
        std::vector<conf::peer_properties> peers;

        for (const Peer_Properties *peer : *fbvec)
        {
            conf::peer_properties properties;

            properties.ip_port.host_address = flatbuff_str_to_sv(peer->host_address());
            properties.ip_port.port = peer->port();
            properties.timestamp = peer->timestamp();
            properties.available_capacity = peer->available_capacity();

            peers.push_back(properties);
        }
        return peers;
    }
} // namespace msg::fbuf::p2pmsg