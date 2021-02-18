#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util/util.hpp"
#include "../hplog.hpp"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../ledger/ledger.hpp"
#include "p2p.hpp"
#include "self_node.hpp"
#include "../unl.hpp"

namespace p2p
{

    // Holds global connected-peers and related objects.
    connected_context ctx;

    uint64_t metric_thresholds[5];
    bool init_success = false;

    /**
     * Initializes the p2p subsystem. Must be called once during application startup.
     * @return 0 for successful initialization. -1 for failure.
     */
    int init()
    {
        metric_thresholds[0] = conf::cfg.mesh.max_bytes_per_min;
        metric_thresholds[1] = conf::cfg.mesh.max_dup_msgs_per_min;
        metric_thresholds[2] = conf::cfg.mesh.max_bad_msgsigs_per_min;
        metric_thresholds[3] = conf::cfg.mesh.max_bad_msgs_per_min;
        metric_thresholds[4] = conf::cfg.mesh.idle_timeout;

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
        {
            // Persist latest known peers information to config before the peer server is stopped.
            {
                std::scoped_lock lock(ctx.server->req_known_remotes_mutex);
                conf::persist_known_peers_config(ctx.server->req_known_remotes);
            }

            ctx.server->stop();
        }
    }

    int start_peer_connections()
    {
        const uint16_t listen_port = conf::cfg.mesh.listen ? conf::cfg.mesh.port : 0;
        ctx.server.emplace(listen_port, metric_thresholds, conf::cfg.mesh.max_bytes_per_msg,
                           conf::cfg.mesh.max_connections, conf::cfg.mesh.max_in_connections_per_host, conf::cfg.mesh.known_peers);
        if (ctx.server->start() == -1)
            return -1;

        LOG_INFO << "Started listening for peer connections on " << std::to_string(conf::cfg.mesh.port);
        return 0;
    }

    int resolve_peer_challenge(peer_comm_session &session, const peer_challenge_response &challenge_resp)
    {
        // Compare the response challenge string with the original issued challenge.
        if (session.issued_challenge != challenge_resp.challenge)
        {
            LOG_DEBUG << "Peer challenge response, challenge invalid.";
            return -1;
        }

        // Verify the challenge signature.
        if (crypto::verify(challenge_resp.challenge, challenge_resp.signature, challenge_resp.pubkey) != 0)
        {
            LOG_DEBUG << "Peer challenge response signature verification failed.";
            return -1;
        }

        // Converting the binary pub key into hexadecimal string.
        std::string pubkeyhex = util::to_hex(challenge_resp.pubkey);

        const int res = challenge_resp.pubkey.compare(conf::cfg.node.public_key);

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

        const auto iter = ctx.peer_connections.find(challenge_resp.pubkey);
        if (iter == ctx.peer_connections.end())
        {
            // Add the new connection straight away, if we haven't seen it before.
            session.uniqueid.swap(pubkeyhex);
            session.pubkey = challenge_resp.pubkey;
            session.is_unl = unl::exists(session.pubkey);
            // Mark the connection as a verified connection.
            session.mark_as_verified();
            // Public key in binary format will be used as the lookup key in storing peer sessions.
            ctx.peer_connections.try_emplace(session.pubkey, &session);

            LOG_DEBUG << "Accepted verified connection [" << session.display_name() << "]";
            return 0;
        }
        else // Peer pub key already exists in our sessions.
        {
            peer_comm_session &ex_session = *iter->second;
            // We don't allow duplicate sessions to the same peer to same direction.
            if (ex_session.is_inbound != session.is_inbound)
            {
                // Decide whether we need to replace existing session with new session.
                const bool replace_needed = ((res < 0 && !ex_session.is_inbound) || (res > 0 && ex_session.is_inbound));
                if (replace_needed)
                {
                    // If we happen to replace a peer session with known IP, transfer required details to the new session.
                    if (!session.known_ipport.has_value())
                        session.known_ipport.swap(ex_session.known_ipport);
                    session.uniqueid.swap(pubkeyhex);
                    session.pubkey = challenge_resp.pubkey;
                    session.is_unl = unl::exists(session.pubkey);
                    // Mark the connection as a verified connection.
                    session.mark_as_verified();

                    ex_session.mark_for_closure();
                    ctx.peer_connections.erase(iter); // remove existing session.
                    // We have to keep the peer requirements of the removed session object.
                    // If not, requirements received prior to connection dropping will be lost.
                    session.need_consensus_msg_forwarding = ex_session.need_consensus_msg_forwarding;
                    // Public key in binary format will be used as the lookup key in storing peer sessions.
                    ctx.peer_connections.try_emplace(session.pubkey, &session); // add new session.

                    LOG_DEBUG << "Replacing existing connection [" << ex_session.display_name() << "] with [" << session.display_name() << "]";
                    return 0;
                }
                else if (!ex_session.known_ipport.has_value() || session.known_ipport.has_value())
                {
                    // If we have any known ip-port info from the new session, transfer them to the existing session.
                    ex_session.known_ipport.swap(session.known_ipport);
                    LOG_DEBUG << "Merging new connection [" << session.display_name() << "] with [" << ex_session.display_name() << "]";
                }
            }

            // Reaching this point means we don't need the new session.
            LOG_DEBUG << "Rejecting new connection [" << session.display_name() << "] in favour of [" << ex_session.display_name() << "]";
            return -1;
        }
    }

    /**
     * Broadcasts the given message to all currently connected outbound peers.
     * @param fbuf Peer outbound message to be broadcasted.
     * @param send_to_self Whether to also send the message to self (this node).
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     * @param unl_only Whether this broadcast is only for the unl nodes.
     */
    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self, const bool is_msg_forwarding, const bool unl_only)
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

        broadcast_message(msg, send_to_self, is_msg_forwarding, unl_only);
    }

    /**
     * Broadcast the given message to all connected outbound peers.
     * @param message Message to be forwarded.
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     * @param unl_only Whether this broadcast is only for the unl nodes.
     * @param skipping_session Session to be skipped in message forwarding(optional).
     */
    void broadcast_message(std::string_view message, const bool send_to_self, const bool is_msg_forwarding, const bool unl_only, const peer_comm_session *skipping_session)
    {
        if (send_to_self)
            self::send(message);

        //Broadcast while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        for (const auto &[k, session] : ctx.peer_connections)
        {
            // Exclude given session if provided.
            // Messages are forwarded only to the requested nodes only in the message forwarding mode.
            if ((skipping_session && skipping_session == session) ||
                (is_msg_forwarding && !session->need_consensus_msg_forwarding) ||
                (unl_only && !session->is_unl))
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
    bool validate_for_peer_msg_forwarding(const peer_comm_session &session, const msg::fbuf::p2pmsg::Container *container, const msg::fbuf::p2pmsg::Message &content_message_type)
    {
        // Checking whether the message forwarding is enabled.
        if (!conf::cfg.mesh.msg_forwarding)
        {
            return false;
        }

        const uint64_t time_now = util::get_epoch_milliseconds();
        // Checking the time to live of the container. The time to live for forwarding is three times the round time.
        if (container->timestamp() < (time_now - (conf::cfg.contract.roundtime * 3)))
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
        self::send(msg);
    }

    /**
     * Sends the given message to a random peer (except self).
     * @param fbuf Peer outbound message to be sent to peer.
     * @param target_pubkey Randomly selected target peer pubkey.
     */
    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf, std::string &target_pubkey)
    {
        //Send while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

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
            peer_comm_session *session = it->second;
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            session->send(msg);
            target_pubkey = session->uniqueid;
            break;
        }
    }

    /**
     * Sends the peer requirement to the given peer session. If a session is not given, broadcast to all the connected peers.
     * @param need_consensus_msg_forwarding True if the number of connections are below the threshold value.
     * @param session The destination peer node.
     */
    void send_peer_requirement_announcement(const bool need_consensus_msg_forwarding, peer_comm_session *session)
    {
        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_peer_requirement_announcement(fbuf, need_consensus_msg_forwarding, ledger::ctx.get_lcl(), ledger::ctx.get_last_primary_shard_id());
        if (session)
        {
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
            session->send(msg);
        }
        else
        {
            broadcast_message(fbuf, false);
        }
    }

    /**
     * Sends theavailable capacity announcement to all the connected peers.
     * @param available_capacity Available capacity of the known peer.
     */
    void send_available_capacity_announcement(const int16_t &available_capacity)
    {
        const uint64_t time_now = util::get_epoch_milliseconds();
        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_available_capacity_announcement(fbuf, available_capacity, time_now, ledger::ctx.get_lcl(), ledger::ctx.get_last_primary_shard_id());
        broadcast_message(fbuf, false);
    }

    /**
     * Send known peer list to a given peer.
     * @param session Session to be sent the peers.
     */
    void send_known_peer_list(peer_comm_session *session)
    {
        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_peer_list_response(fbuf, ctx.server->req_known_remotes, session->known_ipport, ledger::ctx.get_lcl(), ledger::ctx.get_last_primary_shard_id());
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        session->send(msg);
    }

    /**
     * Updates the capacity of the given known peer.
     * @param ip_port Ip and port of the know peer.
     * @param available_capacity Available capacity of the known peer, -1 if number of connections is unlimited.
     * @param timestamp Capacity announced time.
     */
    void update_known_peer_available_capacity(const conf::peer_ip_port &ip_port, const int16_t available_capacity, const uint64_t &timestamp)
    {
        std::scoped_lock<std::mutex> lock(ctx.server->req_known_remotes_mutex);

        const auto itr = std::find_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(), [&](conf::peer_properties &p) { return p.ip_port == ip_port; });
        if (itr != ctx.server->req_known_remotes.end())
        {
            LOG_DEBUG << "Updating peer available capacity: Host address: " << itr->ip_port.host_address << ":" << itr->ip_port.port << ", Capacity: " << std::to_string(available_capacity);
            itr->available_capacity = available_capacity;
            itr->timestamp = timestamp;

            // Sorting the known remote list  according to the weight value after updating the peer properties.
            sort_known_remotes();
        }
    }

    /**
     * Send peer list request to a random peer.
     */
    void send_peer_list_request()
    {
        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_peer_list_request(fbuf, ledger::ctx.get_lcl(), ledger::ctx.get_last_primary_shard_id());
        std::string target_pubkey;
        send_message_to_random_peer(fbuf, target_pubkey);
        LOG_DEBUG << "Peer list request: Requesting from [" << target_pubkey.substr(0, 10) << "]";
    }

    /**
     * Merging the response peer list with the own known peer list.
     * @param peers Incoming peer list.
     */
    void merge_peer_list(const std::vector<conf::peer_properties> &peers)
    {
        std::scoped_lock<std::mutex> lock(ctx.server->req_known_remotes_mutex);

        for (const conf::peer_properties &peer : peers)
        {
            const auto itr = std::find_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(), [&](conf::peer_properties &p) { return p.ip_port == peer.ip_port; });

            // If the new peer is not in the peer list then add to the req_known_remotes
            // Otherwise if new peer is recently updated (timestamp >) replace with the current one.
            if (itr == ctx.server->req_known_remotes.end())
            {
                // If maximum number of peer list reached skip the rest of peers.
                if (ctx.server->req_known_remotes.size() < p2p::PEER_LIST_CAP)
                {
                    ctx.server->req_known_remotes.push_back(peer);
                    LOG_DEBUG << "Adding " + peer.ip_port.host_address + ":" + std::to_string(peer.ip_port.port) + " to the known peer list.";
                }
                else
                {
                    LOG_DEBUG << "Rejecting " + peer.ip_port.host_address + ":" + std::to_string(peer.ip_port.port) + ". Maximum peer count reached.";
                }
            }
            else if (itr->timestamp < peer.timestamp)
            {
                itr->available_capacity = peer.available_capacity;
                itr->timestamp = peer.timestamp;
                LOG_DEBUG << "Replacing " + peer.ip_port.host_address + ":" + std::to_string(peer.ip_port.port) + " in the known peer list.";
            }
        }

        // Sorting the known remote list according to the weight value after merging the peer list.
        sort_known_remotes();
    }

    /**
     * Sorting the known remote list according to the weight value.
     */
    void sort_known_remotes()
    {
        std::sort(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(),
                  [](const conf::peer_properties &p1, const conf::peer_properties &p2) {
                      return get_peer_weight(p1) < 0 || get_peer_weight(p1) > get_peer_weight(p2);
                  });
    }

    /**
     * Calculate the weight value for the peer.
     * @param peer Properties of the peer.
     * @returns -1 if available capacity is unlimited otherwise weight value.
     */
    int32_t get_peer_weight(const conf::peer_properties &peer)
    {
        const uint64_t time_now = util::get_epoch_milliseconds();
        return peer.available_capacity >= 0 ? peer.available_capacity * 1000 * 60 / ceil(time_now - peer.timestamp) : -1;
    }

    /**
     * Calculate and retunrns the available capacity.
     * @returns -1 if available capacity is unlimited otherwise available value.
     */
    int16_t get_available_capacity()
    {
        // If both max_connections and max_known_connections are configured calculate the capacity.
        if (conf::cfg.mesh.max_connections != 0 && conf::cfg.mesh.max_known_connections != 0)
        {
            // If known peer max connection count is equal to the peer max connection count then return 0.
            // Otherwise peer max con count - know peer max con count - inbound peer cons.
            if (conf::cfg.mesh.max_connections != conf::cfg.mesh.max_known_connections)
                return conf::cfg.mesh.max_connections - conf::cfg.mesh.max_known_connections - ctx.peer_connections.size() + ctx.server->known_remote_count;
            else
                return 0;
        }
        else if (conf::cfg.mesh.max_connections != 0 && conf::cfg.mesh.max_known_connections == 0)
            return conf::cfg.mesh.max_connections - ctx.peer_connections.size();
        return -1;
    }

    /**
     * Update the peer trusted status on unl list updates.
    */
    void update_unl_connections()
    {
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        for (const auto &[k, session] : ctx.peer_connections)
        {
            session->is_unl = unl::exists(session->pubkey);
        }
    }

    /**
     * This is a helper method for sequence_hash structure which enables printing it straight away.
    */
    std::ostream &operator<<(std::ostream &output, const sequence_hash &seq_hash)
    {
        output << seq_hash.seq_no << "-" << seq_hash.hash;
        return output;
    }

} // namespace p2p