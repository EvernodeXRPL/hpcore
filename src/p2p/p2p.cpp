#include "../pchheader.hpp"
#include "../comm/comm_server.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../ledger.hpp"

namespace p2p
{

    // Holds global connected-peers and related objects.
    connected_context ctx;

    uint64_t metric_thresholds[4];
    bool init_success = false;

    /**
 * Initializes the p2p subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
    int init()
    {
        metric_thresholds[0] = conf::cfg.peermaxcpm;
        metric_thresholds[1] = conf::cfg.peermaxdupmpm;
        metric_thresholds[2] = conf::cfg.peermaxbadsigpm;
        metric_thresholds[3] = conf::cfg.peermaxbadmpm;

        //Entry point for p2p which will start peer connections to other nodes
        if (start_peer_connections() == -1)
            return -1;

        init_success = true;
        return 0;
    }

    /**
 * Cleanup any running processes.
 */
    void deinit()
    {
        if (init_success)
            ctx.listener.stop();
    }

    int start_peer_connections()
    {
        if (ctx.listener.start(
                conf::cfg.peerport, comm::SESSION_TYPE::PEER, metric_thresholds, conf::cfg.peers, conf::cfg.peermaxsize) == -1)
            return -1;

        LOG_INFO << "Started listening for peer connections on " << std::to_string(conf::cfg.peerport);
        return 0;
    }

    int resolve_peer_challenge(comm::hpws_comm_session &session, const peer_challenge_response &challenge_resp)
    {
        // Compare the response challenge string with the original issued challenge.
        if (session.issued_challenge != challenge_resp.challenge)
        {
            LOG_DEBUG << "Peer challenge response, challenge invalid.";
            return -1;
        }

        // Verify the challenge signature.
        if (crypto::verify(
                challenge_resp.challenge,
                challenge_resp.signature,
                challenge_resp.pubkey) != 0)
        {
            LOG_DEBUG << "Peer challenge response signature verification failed.";
            return -1;
        }

        // Converting the binary pub key into hexadecimal string.
        // This will be used as the lookup key in storing peer sessions.
        std::string pubkeyhex;
        util::bin2hex(pubkeyhex, reinterpret_cast<const unsigned char *>(challenge_resp.pubkey.data()), challenge_resp.pubkey.length());

        const int res = challenge_resp.pubkey.compare(conf::cfg.pubkey);

        // If pub key is greater than our id (< 0), then we should give priority to any existing inbound connection
        // from the same peer and drop the outbound connection.
        // If pub key is lower than our id (> 0), then we should give priority to any existing outbound connection
        // from the same peer and drop the inbound connection.

        // If the pub key is same as ours then we reject the connection.
        if (res == 0)
        {
            LOG_DEBUG << "Pubkey violation. Rejecting new peer connection [" << session.display_name() << "]";
            return -1;
        }

        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        const auto iter = p2p::ctx.peer_connections.find(pubkeyhex);
        if (iter == p2p::ctx.peer_connections.end())
        {
            // Add the new connection straight away, if we haven't seen it before.
            session.uniqueid.swap(pubkeyhex);
            session.challenge_status = comm::CHALLENGE_VERIFIED;
            p2p::ctx.peer_connections.try_emplace(session.uniqueid, &session);
            return 0;
        }
        else // Peer pub key already exists in our sessions.
        {
            comm::hpws_comm_session &ex_session = *iter->second;
            // We don't allow duplicate sessions to the same peer to same direction.
            if (ex_session.is_inbound != session.is_inbound)
            {
                // Decide whether we need to replace existing session with new session.
                const bool replace_needed = ((res < 0 && !ex_session.is_inbound) || (res > 0 && ex_session.is_inbound));
                if (replace_needed)
                {
                    // If we happen to replace a peer session with known IP, transfer required details to the new session.
                    if (session.known_ipport.first.empty())
                        session.known_ipport.swap(ex_session.known_ipport);
                    session.uniqueid.swap(pubkeyhex);
                    session.challenge_status = comm::CHALLENGE_VERIFIED;

                    ex_session.mark_for_closure();
                    p2p::ctx.peer_connections.erase(iter); // remove existing session.
                    // We have to keep the weekly connected status of the removed session object.
                    // If not, connected status received prior to connection dropping will be lost.
                    session.is_weakly_connected = ex_session.is_weakly_connected;
                    p2p::ctx.peer_connections.try_emplace(session.uniqueid, &session); // add new session.

                    LOG_DEBUG << "Replacing existing connection [" << session.display_name() << "]";
                    return 0;
                }
                else if (ex_session.known_ipport.first.empty() || !session.known_ipport.first.empty())
                {
                    // If we have any known ip-port info from the new session, transfer them to the existing session.
                    ex_session.known_ipport.swap(session.known_ipport);
                }
            }

            // Reaching this point means we don't need the new session.
            LOG_DEBUG << "Rejecting new peer connection [" << session.display_name() << "] because existing connection [" << ex_session.display_name() << "] takes priority.";
            return -1;
        }
    }

    /**
     * Broadcasts the given message to all currently connected outbound peers.
     * @param fbuf Peer outbound message to be broadcasted.
     * @param send_to_self Whether to also send the message to self (this node).
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     */
    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self, const bool is_msg_forwarding)
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

        broadcast_message(msg, send_to_self, is_msg_forwarding);
    }

    /**
     * Broadcast the given message to all connected outbound peers.
     * @param message Message to be forwarded.
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     * @param skipping_session Session to be skipped in message forwarding(optional).
     */
    void broadcast_message(std::string_view message, const bool send_to_self, const bool is_msg_forwarding, const comm::comm_session *skipping_session)
    {
        if (send_to_self)
            ctx.self_session.send(message);

        //Broadcast while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        for (const auto &[k, session] : ctx.peer_connections)
        {
            // Exclude given session if provided.
            // Messages are forwarded only to the weakly connected nodes only in the message forwarding mode.
            if ((skipping_session && skipping_session == session) ||
                (is_msg_forwarding && !session->is_weakly_connected))
                continue;

            session->send(message);
        }
    }
    /**
     * Check whether the given message is qualified to be forwarded to peers.
     * @param container The message container.
     * @param content_message_type The message type.
     * @return Returns true if the message is qualified for forwarding to peers. False otherwise.
    */
    bool validate_for_peer_msg_forwarding(const comm::hpws_comm_session &session, const msg::fbuf::p2pmsg::Container *container, const msg::fbuf::p2pmsg::Message &content_message_type)
    {
        // Checking whether the message forwarding is enabled.
        if (!conf::cfg.msgforwarding)
        {
            return false;
        }

        const int64_t time_now = util::get_epoch_milliseconds();
        // Checking the time to live of the container. The time to live for forwarding is three times the round time.
        if (container->timestamp() < (time_now - (conf::cfg.roundtime * 3)))
        {
            LOG_DEBUG << "Peer message is too old for forwarding.";
            return false;
        }
        // Only the selected types of messages are forwarded.
        if (content_message_type == msg::fbuf::p2pmsg::Message_Proposal_Message ||
            content_message_type == msg::fbuf::p2pmsg::Message_NonUnl_Proposal_Message ||
            content_message_type == msg::fbuf::p2pmsg::Message_Npl_Message)
        {
            return true;
        }
        return false;
    }

    /**
 * Sends the given message to self (this node).
 * @param fbuf Peer outbound message to be sent to self.
 */
    void send_message_to_self(const flatbuffers::FlatBufferBuilder &fbuf)
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        ctx.self_session.send(msg);
    }

    /**
 * Sends the given message to a random peer (except self).
 * @param fbuf Peer outbound message to be sent to peer.
 * @param target_pubkey Randomly selected target peer pubkey.
 */
    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf, std::string &target_pubkey)
    {
        //Send while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

        const size_t connected_peers = ctx.peer_connections.size();
        if (connected_peers == 0)
        {
            LOG_DEBUG << "No peers to random send.";
            return;
        }

        while (true)
        {
            // Initialize random number generator with current timestamp.
            const int random_peer_index = (rand() % connected_peers); // select a random peer index.
            auto it = ctx.peer_connections.begin();
            std::advance(it, random_peer_index); //move iterator to point to random selected peer.

            //send message to selected peer.
            comm::hpws_comm_session *session = it->second;
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            session->send(msg);
            target_pubkey = session->uniqueid;
            break;
        }
    }

    /**
     * Sends the connected status broadcast announcement to all the connected peers.
     * @param fbuf Peer outbound message to be sent to peer.
     * @param is_weakly_connected True if the number of connections are below the threshold value.
     */
    void send_connected_status_announcement(flatbuffers::FlatBufferBuilder &fbuf, const bool is_weakly_connected)
    {
        msg::fbuf::p2pmsg::create_msg_for_connected_status_announcement(fbuf, is_weakly_connected, ledger::ctx.get_lcl());
        p2p::broadcast_message(fbuf, false);
    }

} // namespace p2p