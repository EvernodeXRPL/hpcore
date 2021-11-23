#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util/util.hpp"
#include "../util/sequence_hash.hpp"
#include "../hplog.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../ledger/ledger.hpp"
#include "p2p.hpp"
#include "self_node.hpp"
#include "../unl.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

// Maximum no. of peers that will be persisted back to config upon exit.
constexpr size_t MAX_PERSISTED_KNOWN_PEERS = 100;

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
            // If peer discovery was enabled, update latest known peers information to config
            // before the peer server is stopped. (config will permanently save it to disk upon exit)
            if (conf::cfg.mesh.peer_discovery.enabled)
            {
                std::scoped_lock lock(ctx.server->req_known_remotes_mutex);
                const std::vector<peer_properties> &peers = ctx.server->req_known_remotes;
                const size_t count = MIN(MAX_PERSISTED_KNOWN_PEERS, peers.size());
                conf::cfg.mesh.known_peers.clear();
                for (size_t i = 0; i < count; i++)
                    conf::cfg.mesh.known_peers.emplace(peers[i].ip_port);
            }

            ctx.server->stop();
        }
    }

    int start_peer_connections()
    {
        const uint16_t listen_port = conf::cfg.mesh.listen ? conf::cfg.mesh.port : 0;
        std::vector<peer_properties> known_peers;
        for (const conf::peer_ip_port &ipp : conf::cfg.mesh.known_peers)
            known_peers.push_back(peer_properties{ipp, -1, 0});
        ctx.server.emplace(listen_port, metric_thresholds, conf::cfg.mesh.max_bytes_per_msg,
                           conf::cfg.mesh.max_connections, conf::cfg.mesh.max_in_connections_per_host, std::move(known_peers));
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
            if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                LOG_WARNING << "Pubkey violation. Rejecting new peer connection [" << session.display_name() << "].";

            // It's possible, Self node might've been added to the known peers by peer discovery.
            // If so remove the self from known peers.
            if (session.known_ipport.has_value())
            {
                // We set self ip port values so that we can remove self from the future known peer responses.
                self::ip_port = conf::peer_ip_port{session.known_ipport->host_address, session.known_ipport->port};
                {
                    std::scoped_lock lock(ctx.server->req_known_remotes_mutex);
                    ctx.server->req_known_remotes.erase(std::remove_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(),
                                                                       [&](const p2p::peer_properties &peer)
                                                                       {
                                                                           return peer.ip_port.port == session.known_ipport->port;
                                                                       }));
                    ctx.server->known_remote_count = ctx.server->req_known_remotes.size();
                }
                LOG_DEBUG << "Loopback connection detected: Removed self from the peer list.";
                if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                    LOG_WARNING << "Loopback connection detected: Removed self from the peer list. address: |" << (session.known_ipport.has_value() ? session.known_ipport.value().to_string() : "") << "|.";
            }

            return -1;
        }

        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        const auto iter = ctx.peer_connections.find(challenge_resp.pubkey);
        if (iter == ctx.peer_connections.end())
        {
            if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                LOG_WARNING << "Accepted verified connection [" << session.display_name() << "]. address: |" << (session.known_ipport.has_value() ? session.known_ipport.value().to_string() : "") << "|.";

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
                    if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                        LOG_WARNING << "Replacing existing connection [" << ex_session.display_name() << "] with [" << session.display_name() << "]. address: |" << (session.known_ipport.has_value() ? session.known_ipport.value().to_string() : "") << "|.";

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
                    if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                        LOG_WARNING << "Merging new connection [" << session.display_name() << "] with [" << ex_session.display_name() << "]. address: |" << (session.known_ipport.has_value() ? session.known_ipport.value().to_string() : "") << "|.";
                }
            }

            // Reaching this point means we don't need the new session.
            LOG_DEBUG << "Rejecting new connection [" << session.display_name() << "] in favour of [" << ex_session.display_name() << "]";
            if (!session.known_ipport.has_value() || (session.known_ipport.has_value() && session.known_ipport.value().host_address.empty()))
                LOG_WARNING << "Rejecting new connection [" << session.display_name() << "] in favour of [" << ex_session.display_name() << "]. address: |" << (session.known_ipport.has_value() ? session.known_ipport.value().to_string() : "") << "|.";
            return -1;
        }
    }

    /**
     * Broadcasts the given message to all currently connected outbound peers.
     * @param fbuf Peer outbound message to be broadcasted.
     * @param send_to_self Whether to also send the message to self (this node).
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     * @param unl_only Whether this broadcast is only for the unl nodes.
     * @param priority If 1, use high pririty send. Else, use low priority send.
     */
    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self, const bool is_msg_forwarding, const bool unl_only, const uint16_t priority)
    {
        broadcast_message(msg::fbuf::builder_to_string_view(fbuf), send_to_self, is_msg_forwarding, unl_only);
    }

    /**
     * Broadcast the given message to all connected outbound peers.
     * @param message Message to be forwarded.
     * @param is_msg_forwarding Whether this broadcast is for message forwarding.
     * @param unl_only Whether this broadcast is only for the unl nodes.
     * @param skipping_session Session to be skipped in message forwarding(optional).
     * @param priority If 1, use high pririty send. Else, use low priority send.
     */
    void broadcast_message(std::string_view message, const bool send_to_self, const bool is_msg_forwarding, const bool unl_only, const peer_comm_session *skipping_session, const uint16_t priority)
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

            session->send(message, priority);
        }
    }

    /**
     * Check whether the given message is qualified to be forwarded to peers.
     * @param msg_type The message type.
     * @param originated_on The originated epoch of the received message.
     * @return Returns true if the message is qualified for forwarding to peers. False otherwise.
    */
    bool validate_for_peer_msg_forwarding(const peer_comm_session &session, const enum msg::fbuf::p2pmsg::P2PMsgContent msg_type, const uint64_t originated_on)
    {
        // Checking whether the message forwarding is enabled.
        if (!conf::cfg.mesh.msg_forwarding)
        {
            return false;
        }

        // Only the selected types of messages are forwarded.
        if (msg_type == p2pmsg::P2PMsgContent_ProposalMsg ||
            msg_type == p2pmsg::P2PMsgContent_NonUnlProposalMsg ||
            msg_type == p2pmsg::P2PMsgContent_NplMsg)
        {
            // Checking the time to live of the message. The time to live for forwarding is three times the round time.
            const uint64_t time_now = util::get_epoch_milliseconds();
            if (originated_on < (time_now - (conf::cfg.contract.roundtime * 3)))
            {
                LOG_DEBUG << "Peer message is too old for forwarding. type:" << msg_type << " from:" << session.display_name();
                return false;
            }

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
     * @param full_history_only Should send only to a random full history node.
     */
    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf, std::string &target_pubkey, const bool full_history_only)
    {
        //Send while locking the peer_connections.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);

        const size_t connected_peers = ctx.peer_connections.size();
        if (connected_peers == 0)
        {
            LOG_DEBUG << "No peers to random send.";
            return;
        }

        peer_comm_session *session = NULL;

        if (full_history_only)
        {
            // Stores full history session list.
            std::vector<peer_comm_session *> full_history_sessions;
            for (auto [key, session] : ctx.peer_connections)
            {
                if (session->is_full_history)
                    full_history_sessions.push_back(session);
            }

            if (full_history_sessions.size() == 0)
            {
                LOG_DEBUG << "No full history peers to random send.";
                return;
            }
            auto it = full_history_sessions.begin();
            // Initialize random number generator with current timestamp.
            const int random_peer_index = (rand() % full_history_sessions.size()); // Select a random peer index.
            std::advance(it, random_peer_index);                                   // Move iterator to point to random selected peer.
            session = *it;
        }
        else
        {
            // Initialize random number generator with current timestamp.
            auto it = ctx.peer_connections.begin();
            const int random_peer_index = (rand() % connected_peers); // Select a random peer index.
            std::advance(it, random_peer_index);                      // Move iterator to point to random selected peer.
            session = it->second;
        }

        //send message to selected peer.
        session->send(msg::fbuf::builder_to_string_view(fbuf));
        target_pubkey = session->uniqueid;
    }

    /**
     * Handle proposal message. This is called from peer and self message handlers.
    */
    void handle_proposal_message(const p2p::proposal &p)
    {
        // Check the cap and insert proposal with lock.
        std::scoped_lock<std::mutex> lock(ctx.collected_msgs.proposals_mutex);

        // If max number of proposals reached skip the rest.
        if (ctx.collected_msgs.proposals.size() == p2p::PROPOSAL_LIST_CAP)
            LOG_DEBUG << "Proposal rejected. Maximum proposal count reached.";
        else
            ctx.collected_msgs.proposals.push_back(std::move(p));
    }

    /**
     * Handle nonunl proposal message. This is called from peer and self message handlers.
    */
    void handle_nonunl_proposal_message(const p2p::nonunl_proposal &nup)
    {
        // Check the cap and insert proposal with lock.
        std::scoped_lock<std::mutex> lock(ctx.collected_msgs.nonunl_proposals_mutex);

        // If max number of nonunl proposals reached skip the rest.
        if (ctx.collected_msgs.nonunl_proposals.size() == p2p::NONUNL_PROPOSAL_LIST_CAP)
            LOG_DEBUG << "Nonunl proposal rejected. Maximum nonunl proposal count reached. self";
        else
            ctx.collected_msgs.nonunl_proposals.push_back(std::move(nup));
    }

    /**
     * Handle npl message. This is called from peer and self message handlers.
     */
    void handle_npl_message(const p2p::npl_message &npl)
    {
        if (!consensus::push_npl_message(npl))
            LOG_DEBUG << "NPL message from self enqueue failure.";
    }

    /**
     * Sends the peer requirement to the given peer session. If a session is not given, broadcast to all the connected peers.
     * @param need_consensus_msg_forwarding True if the number of connections are below the threshold value.
     * @param session The destination peer node.
     */
    void send_peer_requirement_announcement(const bool need_consensus_msg_forwarding, peer_comm_session *session)
    {
        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_peer_requirement_announcement(fbuf, need_consensus_msg_forwarding);
        if (session)
            session->send(msg::fbuf::builder_to_string_view(fbuf));
        else
            broadcast_message(fbuf, false);
    }

    /**
     * Sends theavailable capacity announcement to all the connected peers.
     * @param available_capacity Available capacity of the known peer.
     */
    void send_available_capacity_announcement(const int16_t &available_capacity)
    {
        const uint64_t time_now = util::get_epoch_milliseconds();
        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_available_capacity_announcement(fbuf, available_capacity, time_now);
        broadcast_message(fbuf, false);
    }

    /**
     * Send known peer list to a given peer.
     * @param session Session to be sent the peers.
     */
    void send_known_peer_list(peer_comm_session *session)
    {
        const std::vector<peer_properties> &peers = ctx.server->req_known_remotes;

        // Add self to known peer announcement (indicated as blank host address).
        // peers.push_back(peer_properties{
        //     conf::peer_ip_port{"", conf::cfg.mesh.port},
        //     status::get_available_mesh_capacity(),
        //     util::get_epoch_milliseconds()});

        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_peer_list_response(fbuf, peers, session->known_ipport);
        session->send(msg::fbuf::builder_to_string_view(fbuf));
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

        const auto itr = std::find_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(), [&](peer_properties &p)
                                      { return p.ip_port == ip_port; });
        if (itr != ctx.server->req_known_remotes.end())
        {
            LOG_DEBUG << "Updating peer available capacity: Host address: " << itr->ip_port.host_address << ":" << itr->ip_port.port << ", Capacity: " << std::to_string(available_capacity);
            itr->available_capacity = available_capacity;
            itr->timestamp = timestamp;

            // Sorting the known remote list according to the weight value after updating the peer properties.
            sort_known_remotes();
        }
    }

    /**
     * Send peer list request to a random peer.
     */
    void send_peer_list_request()
    {
        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_peer_list_request(fbuf);
        std::string target_pubkey;
        send_message_to_random_peer(fbuf, target_pubkey);

        if (!target_pubkey.empty())
            LOG_DEBUG << "Peer list requested from [" << target_pubkey.substr(0, 10) << "]";
    }

    /**
     * Merging the response peer list with the own known peer list.
     * @param merge_peers Peers that must be merged with existing known peers.
     * @param remove_peers Peers that must be removed from existing known peers.
     * @param from The session that sent us the peer list.
     */
    void merge_peer_list(const std::string &caller, const std::vector<peer_properties> *merge_peers, const std::vector<peer_properties> *remove_peers, const p2p::peer_comm_session *from)
    {
        std::scoped_lock<std::mutex> lock(ctx.server->req_known_remotes_mutex);

        if (merge_peers)
        {
            for (const peer_properties &peer : *merge_peers)
            {
                if (peer.ip_port.host_address.empty())
                {
                    LOG_WARNING << caller << " BLANKIP RECEIVED " << peer.ip_port.to_string() << " from:" << (from ? from->display_name() : "");
                    continue;
                }

                // If the peer address is indicated as empty, that is the entry for the peer who sent us this.
                // We then fill that up with the host address we see for that peer.
                // if (from && peer.ip_port.host_address.empty())
                // {
                //     peer.ip_port.host_address = from->host_address;
                // }

                // If the peer is self, we won't add to the known peer list.
                if (self::ip_port.has_value() && self::ip_port == peer.ip_port)
                {
                    LOG_DEBUG << "Rejecting " + peer.ip_port.to_string() + ". Loopback connection.";
                    continue;
                }

                const auto itr = std::find_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(), [&](peer_properties &p)
                                              { return p.ip_port == peer.ip_port; });

                // If the new peer is not in the peer list then add to the req_known_remotes
                // Otherwise if new peer is recently updated (timestamp >) replace with the current one.
                if (itr == ctx.server->req_known_remotes.end())
                {
                    // If maximum number of peer list reached skip the rest of peers.
                    if (ctx.server->req_known_remotes.size() < p2p::PEER_LIST_CAP)
                    {
                        ctx.server->req_known_remotes.push_back(peer);
                        LOG_DEBUG << "Adding " + peer.ip_port.to_string() + " to the known peer list.";
                    }
                    else
                    {
                        LOG_DEBUG << "Rejecting " + peer.ip_port.to_string() + ". Maximum peer count reached.";
                    }
                }
                else if (itr->timestamp < peer.timestamp)
                {
                    itr->available_capacity = peer.available_capacity;
                    itr->timestamp = peer.timestamp;
                    LOG_DEBUG << "Replacing " + peer.ip_port.to_string() + " in the known peer list.";
                }
            }
        }

        if (remove_peers)
        {
            for (const peer_properties &peer : *remove_peers)
            {
                const auto itr = std::find_if(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(), [&](peer_properties &p)
                                              { return p.ip_port == peer.ip_port; });

                if (itr != ctx.server->req_known_remotes.end())
                {
                    LOG_DEBUG << "Removing " << peer.ip_port.to_string() << " from known peer list.";
                    ctx.server->req_known_remotes.erase(itr);
                }
            }
        }

        // Sorting the known remote list according to the weight value after merging the peer list.
        if (merge_peers || remove_peers)
            sort_known_remotes();
    }

    /**
     * Sorting the known remote list according to the weight value.
     */
    void sort_known_remotes()
    {
        const uint64_t time_now = util::get_epoch_milliseconds();
        for (peer_properties &peer : ctx.server->req_known_remotes)
        {
            const uint64_t time_diff = (time_now > peer.timestamp) ? (time_now - peer.timestamp) : 1;
            peer.weight = peer.available_capacity >= 0 ? (peer.available_capacity * 1000 * 60) / time_diff : -1;
        }

        std::sort(ctx.server->req_known_remotes.begin(), ctx.server->req_known_remotes.end(),
                  [](const peer_properties &p1, const peer_properties &p2)
                  {
                      return (p1.weight > p2.weight);
                  });
    }

    /**
     * Calculate and retunrns the available capacity.
     * @returns -1 if available capacity is unlimited otherwise available value.
     */
    int16_t calculate_available_capacity()
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

} // namespace p2p