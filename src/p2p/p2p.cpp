#include "../pchheader.hpp"
#include "../comm/comm_server.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"

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

    int resolve_peer_challenge(comm::comm_session &session, const peer_challenge_response &challenge_resp)
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

        // If pub key is same as our (self) pub key, then this is the loopback connection to ourselves.
        // Hence we must keep the connection but only one of two sessions must be added to peer_connections.
        // If pub key is greater than our id (< 0), then we should give priority to any existing inbound connection
        // from the same peer and drop the outbound connection.
        // If pub key is lower than our id (> 0), then we should give priority to any existing outbound connection
        // from the same peer and drop the inbound connection.

        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        const auto iter = p2p::ctx.peer_connections.find(pubkeyhex);
        if (iter == p2p::ctx.peer_connections.end())
        {
            // Add the new connection straight away, if we haven't seen it before.
            session.is_self = (res == 0);
            session.uniqueid.swap(pubkeyhex);
            session.challenge_status = comm::CHALLENGE_VERIFIED;
            p2p::ctx.peer_connections.try_emplace(session.uniqueid, &session);
            return 0;
        }
        else if (res == 0) // New connection is self (There can be two sessions for self (inbound/outbound))
        {
            session.is_self = true;
            session.uniqueid.swap(pubkeyhex);
            session.challenge_status = comm::CHALLENGE_VERIFIED;
            return 0;
        }
        else // New connection is not self but peer pub key already exists in our sessions.
        {
            comm::comm_session &ex_session = *iter->second;
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
                    p2p::ctx.peer_connections.erase(iter);                             // remove existing session.
                    p2p::ctx.peer_connections.try_emplace(session.uniqueid, &session); // add new session.

                    LOG_DEBUG << "Replacing existing connection [" << session.uniqueid.substr(0, 10) << "]";
                    return 0;
                }
                else if (ex_session.known_ipport.first.empty() || !session.known_ipport.first.empty())
                {
                    // If we have any known ip-port info from the new session, transfer them to the existing session.
                    ex_session.known_ipport.swap(session.known_ipport);
                }
            }

            // Reaching this point means we don't need the new session.
            LOG_DEBUG << "Rejecting new peer connection because existing connection takes priority [" << pubkeyhex.substr(0, 10) << "]";
            return -1;
        }
    }

    /**
     * Broadcasts the given message to all currently connected outbound peers.
     * @param fbuf Peer outbound message to be broadcasted.
     * @param send_to_self Whether to also send the message to self (this node).
     */
    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self)
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        broadcast_message(msg, send_to_self);
    }

    /**
     * Broadcast the given message to all connected outbound peers.
     * @param message Message to be forwarded.
     * @param skipping_session Session to be skipped in message forwarding(optional).
     */
    void broadcast_message(std::string_view message, const bool send_to_self, const comm::comm_session *skipping_session)
    {
        if (ctx.peer_connections.size() == 0)
        {
            LOG_DEBUG << "No peers to broadcast (not even self). Cannot broadcast.";
            return;
        }

        //Broadcast while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        for (const auto &[k, session] : ctx.peer_connections)
        {
            // Exclude given session and self if provided.
            if ((!send_to_self && session->is_self) || (skipping_session && skipping_session == session))
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
    bool validate_for_peer_msg_forwarding(const comm::comm_session &session, const msg::fbuf::p2pmsg::Container *container, const msg::fbuf::p2pmsg::Message &content_message_type)
    {
        // Checking whether the message forwarding is enabled and skip if the message is sent from self.
        if (!conf::cfg.msgforwarding || session.is_self)
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
        //Send while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

        // Find the peer session connected to self.
        const auto peer_itr = ctx.peer_connections.find(conf::cfg.pubkeyhex);
        if (peer_itr != ctx.peer_connections.end())
        {
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            comm::comm_session *session = peer_itr->second;
            session->send(msg);
        }
    }

    /**
 * Sends the given message to a random peer (except self).
 * @param fbuf Peer outbound message to be sent to peer.
 */
    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf)
    {
        //Send while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

        const size_t connected_peers = ctx.peer_connections.size();
        if (connected_peers == 0)
        {
            LOG_DEBUG << "No peers to random send.";
            return;
        }
        else if (connected_peers == 1 && ctx.peer_connections.begin()->second->is_self)
        {
            LOG_DEBUG << "Only self is connected. Cannot random send.";
            return;
        }

        while (true)
        {
            // Initialize random number generator with current timestamp.
            const int random_peer_index = (rand() % connected_peers); // select a random peer index.
            auto it = ctx.peer_connections.begin();
            std::advance(it, random_peer_index); //move iterator to point to random selected peer.

            //send message to selected peer.
            comm::comm_session *session = it->second;
            if (!session->is_self) // Exclude self peer.
            {
                std::string_view msg = std::string_view(
                    reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

                session->send(msg);
                break;
            }
        }
    }

} // namespace p2p