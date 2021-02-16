#include "../../pchheader.hpp"
#include "../../conf.hpp"
#include "../../crypto.hpp"
#include "../../util/util.hpp"
#include "../../hplog.hpp"
#include "../../util/h32.hpp"
#include "../../unl.hpp"
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
            const uint64_t time_now = util::get_epoch_milliseconds();
            if (container->timestamp() < (time_now - conf::cfg.contract.roundtime * 4))
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

        //validate if the message is not from a unl node.
        if (!unl::exists(std::string(msg_pubkey)))
        {
            LOG_DEBUG << "Peer message pubkey verification failed. Not a UNL node.";
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
     * @return Peer challenge struct.
     */
    const p2p::peer_challenge get_peer_challenge_from_msg(const Peer_Challenge_Message &msg)
    {
        return {
            std::string(flatbuff_str_to_sv(msg.contract_id())),
            msg.roundtime(),
            std::string(flatbuff_str_to_sv(msg.challenge()))};
    }

    /**
     * Creates a peer challenge response struct from the given peer challenge response message.
     * @param The Flatbuffer peer challenge response message received from the peer.
     * @return A peer challenge response struct representing the message.
     */
    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const Peer_Challenge_Response_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey)
    {
        p2p::peer_challenge_response pchalresp;

        pchalresp.challenge = flatbuff_str_to_sv(msg.challenge());
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
        p.recv_timestamp = util::get_epoch_milliseconds();
        p.time = msg.time();
        p.nonce = flatbuff_bytes_to_sv(msg.nonce());
        p.stage = msg.stage();
        p.lcl = flatbuff_bytes_to_sv(lcl);
        p.state_hash = flatbuff_bytes_to_sv(msg.state_hash());
        p.patch_hash = flatbuff_bytes_to_sv(msg.patch_hash());

        if (msg.users())
            p.users = flatbuf_bytearrayvector_to_stringlist(msg.users());

        if (msg.input_hashes())
            p.input_hashes = flatbuf_bytearrayvector_to_stringlist(msg.input_hashes());

        if (msg.output_hash())
            p.output_hash = flatbuff_bytes_to_sv(msg.output_hash());

        if (msg.output_sig())
            p.output_sig = flatbuff_bytes_to_sv(msg.output_sig());

        return p;
    }

    /**
     * Creates a history request struct from the given history request message.
     * @param msg Flatbuffer History request message received from the peer.
     * @return A History request struct representing the message.
     */
    const p2p::history_request create_history_request_from_msg(const History_Request_Message &msg, const flatbuffers::Vector<uint8_t> *lcl)
    {
        p2p::history_request hr;

        if (lcl)
            hr.requester_lcl = flatbuff_bytes_to_sv(lcl);

        if (msg.required_lcl())
            hr.required_lcl = flatbuff_bytes_to_sv(msg.required_lcl());

        return hr;
    }

    /**
     * Creates a hpfs request struct from the given hpfs request message.
     * @param msg Flatbuffer State request message received from the peer.
     * @return A hpfs request struct representing the message.
     */
    const p2p::hpfs_request create_hpfs_request_from_msg(const Hpfs_Request_Message &msg)
    {
        p2p::hpfs_request hr;
        hr.mount_id = msg.mount_id();
        hr.block_id = msg.block_id();
        hr.is_file = msg.is_file();
        hr.parent_path = flatbuff_str_to_sv(msg.parent_path());
        hr.expected_hash = flatbuff_bytes_to_hash(msg.expected_hash());

        return hr;
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
                sv_to_flatbuff_str(builder, conf::cfg.contract.id),
                conf::cfg.contract.roundtime,
                sv_to_flatbuff_str(builder, challenge));

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
                sv_to_flatbuff_str(builder, challenge),
                sv_to_flatbuff_bytes(builder, crypto::sign(challenge, conf::cfg.node.private_key)));

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
                sv_to_flatbuff_bytes(builder, p.nonce),
                stringlist_to_flatbuf_bytearrayvector(builder, p.users),
                stringlist_to_flatbuf_bytearrayvector(builder, p.input_hashes),
                sv_to_flatbuff_bytes(builder, p.output_hash),
                sv_to_flatbuff_bytes(builder, p.output_sig),
                hash_to_flatbuff_bytes(builder, p.state_hash),
                hash_to_flatbuff_bytes(builder, p.patch_hash));

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
                sv_to_flatbuff_bytes(builder, hr.required_lcl));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_History_Request_Message, hrmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, hr.requester_lcl, false);
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
     * Create hpfs request message from the given hpfs request struct.
     * @param container_builder Flatbuffer builder for the container message.
     * @param hr The hpfs request struct to be placed in the container message.
     */
    void create_msg_from_hpfs_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::hpfs_request &hr, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        flatbuffers::Offset<Hpfs_Request_Message> srmsg =
            CreateHpfs_Request_Message(
                builder,
                hr.mount_id,
                sv_to_flatbuff_str(builder, hr.parent_path),
                hr.is_file,
                hr.block_id,
                hash_to_flatbuff_bytes(builder, hr.expected_hash));

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_Hpfs_Request_Message, srmsg.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, false);
    }

    /**
     * Create content response message from the given content response.
     * @param container_builder Flatbuffer builder for the container message.
     * @param path The path of the directory.
     * @param mount_id The mount id of the relavent hpfs mount.
     * @param hash_nodes File or directory entries with hashes in the given parent path.
     * @param expected_hash The exptected hash of the requested path.
     * @param lcl Lcl to be include in the container msg.
     */
    void create_msg_from_fsentry_response(
        flatbuffers::FlatBufferBuilder &container_builder, const std::string_view path, const uint32_t mount_id,
        std::vector<hpfs::child_hash_node> &hash_nodes, util::h32 expected_hash, std::string_view lcl)
    {
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Fs_Entry_Response> resp =
            CreateFs_Entry_Response(
                builder,
                hpfsfshashentry_to_flatbuff_hpfsfshashentry(builder, hash_nodes));

        const flatbuffers::Offset<Hpfs_Response_Message> st_resp = CreateHpfs_Response_Message(
            builder, Hpfs_Response_Fs_Entry_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, expected_hash),
            sv_to_flatbuff_str(builder, path), mount_id);

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_Hpfs_Response_Message, st_resp.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
     * Create content response message from the given content response.
     * @param container_builder Flatbuffer builder for the container message.
     * @param path The path of the directory.
     * @param mount_id The mount id of the relavent hpfs mount.
     * @param hashmap Hashmap of the file
     * @param lcl Lcl to be include in the container msg.
     */
    void create_msg_from_filehashmap_response(
        flatbuffers::FlatBufferBuilder &container_builder, std::string_view path, const uint32_t mount_id,
        std::vector<util::h32> &hashmap, std::size_t file_length, util::h32 expected_hash, std::string_view lcl)
    {
        // todo:get a average propsal message size and allocate content builder based on that.
        flatbuffers::FlatBufferBuilder builder(1024);

        std::string_view hashmap_sv(reinterpret_cast<const char *>(hashmap.data()), hashmap.size() * sizeof(util::h32));

        const flatbuffers::Offset<File_HashMap_Response> resp =
            CreateFile_HashMap_Response(
                builder,
                file_length,
                sv_to_flatbuff_bytes(builder, hashmap_sv));

        const flatbuffers::Offset<Hpfs_Response_Message> st_resp = CreateHpfs_Response_Message(
            builder,
            Hpfs_Response_File_HashMap_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, expected_hash),
            sv_to_flatbuff_str(builder, path), mount_id);

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_Hpfs_Response_Message, st_resp.Union());
        builder.Finish(message); // Finished building message content to get serialised content.

        // Now that we have built the content message,
        // we need to sign it and place it inside a container message.
        create_containermsg_from_content(container_builder, builder, lcl, true);
    }

    /**
     * Create content response message from the given content response.
     * @param container_builder Flatbuffer builder for the container message.
     * @param block_resp Block response struct to place in the message.
     * @param mount_id The mount id of the relavent hpfs mount.
     * @param lcl Lcl to be include in the container message.
     */
    void create_msg_from_block_response(flatbuffers::FlatBufferBuilder &container_builder, p2p::block_response &block_resp, const uint32_t mount_id, std::string_view lcl)
    {
        // todo:get a average propsal message size and allocate content builder based on that.
        flatbuffers::FlatBufferBuilder builder(1024);

        const flatbuffers::Offset<Block_Response> resp =
            CreateBlock_Response(
                builder,
                block_resp.block_id,
                sv_to_flatbuff_bytes(builder, block_resp.data));

        const flatbuffers::Offset<Hpfs_Response_Message> st_resp = CreateHpfs_Response_Message(
            builder,
            Hpfs_Response_Block_Response,
            resp.Union(),
            hash_to_flatbuff_bytes(builder, block_resp.hash),
            sv_to_flatbuff_str(builder, block_resp.path), mount_id);

        flatbuffers::Offset<Content> message = CreateContent(builder, Message_Hpfs_Response_Message, st_resp.Union());
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

            sig_offset = sv_to_flatbuff_bytes(container_builder, crypto::sign(content_to_sign, conf::cfg.node.private_key));
            pubkey_offset = sv_to_flatbuff_bytes(container_builder, conf::cfg.node.public_key);
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

    const std::unordered_map<std::string, std::list<usr::submitted_user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec)
    {
        std::unordered_map<std::string, std::list<usr::submitted_user_input>> map;
        map.reserve(fbvec->size());
        for (const UserInputGroup *group : *fbvec)
        {
            std::list<usr::submitted_user_input> user_inputs_list;

            for (const auto msg : *group->messages())
            {
                user_inputs_list.push_back(usr::submitted_user_input{
                    std::string(flatbuff_bytes_to_sv(msg->input_container())),
                    std::string(flatbuff_bytes_to_sv(msg->signature())),
                    static_cast<util::PROTOCOL>(msg->protocol())});
            }

            map.emplace(flatbuff_bytes_to_sv(group->pubkey()), std::move(user_inputs_list));
        }
        return map;
    }

    //---Conversion helpers from std data types to flatbuffers data types---//
    //---These are used in constructing Flatbuffer messages using builders---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::list<usr::submitted_user_input>> &map)
    {
        std::vector<flatbuffers::Offset<UserInputGroup>> fbvec;
        fbvec.reserve(map.size());
        for (const auto &[pubkey, msglist] : map)
        {
            std::vector<flatbuffers::Offset<UserInput>> fbmsgsvec;
            for (const usr::submitted_user_input &msg : msglist)
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
            std::list<usr::submitted_user_input> msglist;

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

    void flatbuf_hpfsfshashentry_to_hpfsfshashentry(std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entries, const flatbuffers::Vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>> *fhashes)
    {
        for (const Hpfs_FS_Hash_Entry *f_hash : *fhashes)
        {
            p2p::hpfs_fs_hash_entry entry;
            entry.name = flatbuff_str_to_sv(f_hash->name());
            entry.is_file = f_hash->is_file();
            entry.hash = flatbuff_bytes_to_hash(f_hash->hash());

            fs_entries.emplace(entry.name, std::move(entry));
        }
    }

    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>>>
    hpfsfshashentry_to_flatbuff_hpfsfshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes)
    {
        std::vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>> fbvec;
        fbvec.reserve(hash_nodes.size());
        for (auto const &hash_node : hash_nodes)
        {
            flatbuffers::Offset<Hpfs_FS_Hash_Entry> hpfs_fs_entry = CreateHpfs_FS_Hash_Entry(
                builder,
                sv_to_flatbuff_str(builder, hash_node.name),
                hash_node.is_file,
                hash_to_flatbuff_bytes(builder, hash_node.hash));

            fbvec.push_back(hpfs_fs_entry);
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