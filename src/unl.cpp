#include "util/util.hpp"
#include "hplog.hpp"
#include "conf.hpp"
#include "unl.hpp"
#include "crypto.hpp"
#include "p2p/p2p.hpp"
#include "./msg/fbuf/p2pmsg_helpers.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    std::set<std::string> list; // List of binary pubkeys of UNL.
    std::string json_list;      // Stringified json array of UNL. (To be fed into the contract args)
    std::shared_mutex unl_mutex;
    std::string hash;
    sync_context sync_ctx;
    bool init_success = false;
    constexpr uint16_t SYNCER_IDLE_WAIT = 20; // unl syncer loop sleep time (milliseconds).

    // Max no. of repetitive reqeust resubmissions before abandoning the sync.
    constexpr uint16_t ABANDON_THRESHOLD = 10;

    // No. of milliseconds to wait before resubmitting a request.
    uint16_t REQUEST_RESUBMIT_TIMEOUT;

    /**
     * Performs startup activitites related to unl list.
     * @return 0 for successful initialization. -1 for failure.
     */
    int init()
    {
        if (conf::cfg.contract.unl.empty())
            return -1;

        std::unique_lock lock(unl_mutex);
        list = conf::cfg.contract.unl;
        // Update the own node's unl status.
        conf::cfg.node.is_unl = (list.find(conf::cfg.node.public_key) != list.end());
        update_json_list();
        hash = calculate_hash(list);
        sync_ctx.unl_sync_thread = std::thread(unl_syncer_loop);
        REQUEST_RESUBMIT_TIMEOUT = conf::cfg.contract.roundtime;
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            sync_ctx.is_shutting_down = true;
            sync_ctx.unl_sync_thread.join();
        }
    }

    size_t count()
    {
        std::shared_lock lock(unl_mutex);
        return list.size();
    }

    std::set<std::string> get()
    {
        std::shared_lock lock(unl_mutex);
        return list;
    }

    std::string get_json()
    {
        std::shared_lock lock(unl_mutex);
        return json_list;
    }

    /**
     * Check whether the given pubkey is in the unl list.
     * @param bin_pubkey Pubkey to check for existence.
     * @return Return true if the given pubkey is in the unl list.
    */
    bool exists(const std::string &bin_pubkey)
    {
        std::shared_lock lock(unl_mutex);
        return list.find(bin_pubkey) != list.end();
    }

    /**
     * Called by consensus to apply unl changesets that reached consensus.
     */
    void apply_changeset(const std::set<std::string> &additions, const std::set<std::string> &removals)
    {
        if (additions.empty() && removals.empty())
            return;

        bool is_updated = false;
        {
            std::unique_lock lock(unl_mutex);
            for (const std::string &pubkey : additions)
            {
                const auto [ele, is_success] = list.emplace(pubkey);
                if (is_success)
                    is_updated = true;
            }

            for (const std::string &pubkey : removals)
            {
                if (list.erase(pubkey))
                    is_updated = true;
            }

            if (is_updated)
            {
                update_json_list();
                conf::persist_unl_update(list);
                hash = calculate_hash(list);
                LOG_INFO << "UNL updated. Count:" << list.size();
                // Update the own node's unl status.
                conf::cfg.node.is_unl = (list.find(conf::cfg.node.public_key) != list.end());
            }
        }

        // Update the is_unl flag of peer sessions.
        if (is_updated)
            p2p::update_unl_connections();
    }

    /**
     * Replace the unl list from the received new unl list after verifying it.
     * @param new_list The received unl list from a random peer.
     * @return Returns -1 on verification failure and 0 on successful replacement.
    */
    int verify_and_replace(const std::set<std::string> &new_list)
    {
        const std::string new_unl_hash = calculate_hash(new_list);
        if (new_unl_hash != sync_ctx.target_unl)
        {
            LOG_INFO << "Hash verification on received unl list failed.";
            return -1;
        }

        {
            std::unique_lock lock(unl_mutex);
            list = new_list;
            update_json_list();
            conf::persist_unl_update(list);
            hash = new_unl_hash;
            // Update the own node's unl status.
            conf::cfg.node.is_unl = (list.find(conf::cfg.node.public_key) != list.end());
        }

        // Update the is_unl flag of peer sessions.
        p2p::update_unl_connections();
        return 0;
    }

    void update_json_list()
    {
        std::ostringstream os;
        os << "[";
        for (auto pk = list.begin(); pk != list.end(); pk++)
        {
            if (pk != list.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary pubkey into hex.
            std::string pubkeyhex;
            util::bin2hex(
                pubkeyhex,
                reinterpret_cast<const unsigned char *>(pk->data()) + 1,
                pk->length() - 1);

            os << "\"" << pubkeyhex << "\"";
        }
        os << "]";
        json_list = os.str();
    }

    std::string get_hash()
    {
        std::shared_lock lock(unl_mutex);
        return hash;
    }

    /**
     * Calculate hash of the given set.
     * @param unl_list UNL list.
     * @return Returns the generated hash of the given list.
    */
    std::string calculate_hash(const std::set<std::string> &new_list)
    {
        std::vector<std::string_view> unl_vector(new_list.begin(), new_list.end());
        return crypto::get_hash(unl_vector);
    }

    /**
     * Set sync target to the given unl hash and start syncing.
     * @param target_unl_hash The majority unl from the consensus.
    */
    void set_sync_target(std::string_view target_unl_hash)
    {
        if (sync_ctx.is_shutting_down)
            return;

        std::scoped_lock<std::mutex> lock(sync_ctx.target_unl_mutex);
        if (sync_ctx.target_unl != target_unl_hash)
        {
            sync_ctx.is_syncing = true;
            sync_ctx.target_unl = target_unl_hash;
            sync_ctx.target_requested_on = 0;
            sync_ctx.request_submissions = 0;
            LOG_INFO << "unl sync: Syncing for target:" << hash_bin2hex(sync_ctx.target_unl).substr(0, 10) << " (current:" << hash_bin2hex(get_hash()).substr(0, 10) << ")";
        }
    }

    /**
     * Create and send unl request to random node from the unl list.
     */
    void send_unl_sync_request()
    {
        const uint64_t time_now = util::get_epoch_milliseconds();
        // Check whether we need to send any requests or abandon the sync due to timeout.
        if ((sync_ctx.target_requested_on == 0) ||                                // Initial request.
            (time_now - sync_ctx.target_requested_on) > REQUEST_RESUBMIT_TIMEOUT) // Request resubmission.
        {
            if (sync_ctx.request_submissions < ABANDON_THRESHOLD)
            {
                p2p::unl_sync_request unl_sync_message;
                unl_sync_message.required_unl = sync_ctx.target_unl;

                flatbuffers::FlatBufferBuilder fbuf(1024);
                p2pmsg::create_msg_from_unl_sync_request(fbuf, unl_sync_message);

                std::string target_pubkey;
                p2p::send_message_to_random_peer(fbuf, target_pubkey);

                LOG_DEBUG << "UNL list requested from [" << target_pubkey.substr(0, 10) << "]. Required unl hash:" << hash_bin2hex(sync_ctx.target_unl).substr(0, 10);
                sync_ctx.target_requested_on = time_now;
                sync_ctx.request_submissions++;
            }
            else
            {
                LOG_INFO << "unl sync: Resubmission threshold exceeded. Abandoning sync.";
                sync_ctx.clear_target();
            }
        }
    }

    /**
     * Perform unl syncing and serving.
     */
    void unl_syncer_loop()
    {
        util::mask_signal();

        LOG_INFO << "unl sync: Worker started.";

        while (!sync_ctx.is_shutting_down)
        {
            // Indicates whether any requests/responses were processed in the previous loop iteration.
            bool prev_processed = false;
            {
                std::scoped_lock<std::mutex> lock(sync_ctx.target_unl_mutex);
                if (!sync_ctx.target_unl.empty())
                    send_unl_sync_request();

                if (!sync_ctx.target_unl.empty() && check_unl_sync_responses() == 1)
                    prev_processed = true;
            }

            if (check_unl_sync_requests() == 1)
                prev_processed = true;

            // Wait a small delay if there were no requests/responses processed during previous iteration.
            if (!prev_processed)
                util::sleep(SYNCER_IDLE_WAIT);
        }

        LOG_INFO << "unl sync: Worker stopped.";
    }

    std::string hash_bin2hex(std::string_view hash)
    {
        // Get hex from binary hash.
        std::string unl_hash_hex;
        util::bin2hex(unl_hash_hex,
                      reinterpret_cast<const unsigned char *>(hash.data()),
                      hash.size());
        return unl_hash_hex;
    }

    /**
     * Process any unl sync requests received.
     * @return Returns 0 if no requests were processed and returns 1 if atleast one request is served.
     */
    int check_unl_sync_requests()
    {
        // Move over the collected sync requests to the local list.
        std::list<std::pair<std::string, p2p::unl_sync_request>> unl_requests;
        {
            std::scoped_lock<std::mutex>(sync_ctx.list_mutex);
            unl_requests.splice(unl_requests.end(), sync_ctx.collected_unl_sync_requests);
        }

        const std::string unl_hash = get_hash();

        std::shared_lock lock(unl_mutex);
        for (const auto &[session_id, unl_request] : unl_requests)
        {
            // First check whether we are at the required unl state.
            if (unl_request.required_unl != unl_hash)
                continue;

            p2p::unl_sync_response resp;
            resp.requester_unl = unl_hash;
            resp.unl_list = list;

            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2pmsg::create_msg_from_unl_sync_response(fbuf, resp);

            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            // Find the peer that we should send the unl response to.
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
            const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

            if (peer_itr != p2p::ctx.peer_connections.end())
            {
                comm::comm_session *session = peer_itr->second;
                session->send(msg);
            }
        }

        return unl_requests.empty() ? 0 : 1;
    }

    /**
     * Check for any unl sync responses received.
     * @return Returns 0 if no responses were processed and returns 1 if atleast one response was processed.
     */
    int check_unl_sync_responses()
    {
        // Move over the collected sync response to the local list.
        std::list<p2p::unl_sync_response> unl_responses;
        {
            std::scoped_lock<std::mutex>(sync_ctx.list_mutex);
            unl_responses.splice(unl_responses.end(), sync_ctx.collected_unl_sync_responses);
        }

        if (!sync_ctx.target_unl.empty())
        {
            // Scan any queued unl sync responses.
            // Only process the first successful item which matches with our target unl.
            for (const p2p::unl_sync_response &unl : unl_responses)
            {
                if (unl.requester_unl == sync_ctx.target_unl && verify_and_replace(unl.unl_list) != -1)
                {
                    LOG_INFO << "unl sync: Sync complete. New unl:" << hash_bin2hex(sync_ctx.target_unl).substr(0, 10);
                    sync_ctx.clear_target();
                }
            }
        }
        return unl_responses.empty() ? 0 : 1;
    }

} // namespace unl
