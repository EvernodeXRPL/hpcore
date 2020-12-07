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
    constexpr uint16_t SYNCER_IDLE_WAIT = 20;     // unl syncer loop sleep time (milliseconds).

    /**
     * Called by conf during startup to populate configured unl list.
     */
    void init(const std::set<std::string> &init_list)
    {
        if (init_list.empty())
            return;

        std::unique_lock lock(unl_mutex);
        list = init_list;
        update_json_list();
        hash = calculate_hash(list);
        sync_ctx.unl_sync_thread = std::thread(unl_syncer_loop);
        init_success = true;
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
     * Called by contract to update unl at runtime.
     */
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals)
    {
        if (additions.empty() && removals.empty())
            return;

        std::unique_lock lock(unl_mutex);
        const size_t initial_count = list.size();

        for (const std::string &pubkey : additions)
            list.emplace(pubkey);

        for (const std::string &pubkey : removals)
            list.erase(pubkey);

        update_json_list();
        conf::persist_unl_update(list);
        hash = calculate_hash(list);

        const size_t updated_count = list.size();

        // Unlock unique lock. A shared lock is applied to the list inside the update unl connection function
        // because it use unl::exists function call.
        lock.unlock();

        // Update the is_unl flag of peer sessions.
        if (initial_count != updated_count)
            p2p::update_unl_connections();

        LOG_INFO << "UNL updated. Count:" << updated_count;
    }

    /**
     * Replace the unl list from the received new unl list after verifying it.
     * @param new_list The received unl list from a random peer.
     * @return Returns -1 on verification failure and 0 on successful replacement.
    */
    int verify_and_replace(const std::set<std::string> &new_list)
    {
        if (calculate_hash(new_list) != sync_ctx.target_unl)
        {
            LOG_INFO << "Hash verification on received unl list failed.";
            return -1;
        }

        std::unique_lock lock(unl_mutex);
        list = new_list;
        update_json_list();
        conf::persist_unl_update(list);
        hash = calculate_hash(list);
        lock.unlock();

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
        if (get_hash() != target_unl_hash)
        {
            std::scoped_lock<std::mutex> lock(sync_ctx.target_unl_mutex);
            sync_ctx.is_syncing = true;
            sync_ctx.target_unl = target_unl_hash;
            send_unl_sync_request(target_unl_hash);
        }
    }

    /**
     * Create and send unl request to random node from the unl list.
     * @param required_unl Required unl.
     */
    void send_unl_sync_request(std::string_view required_unl)
    {
        p2p::unl_sync_request unl_sync_message;
        unl_sync_message.required_unl = required_unl;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_unl_sync_request(fbuf, unl_sync_message);

        std::string target_pubkey;
        p2p::send_message_to_random_peer(fbuf, target_pubkey);

        LOG_INFO << "UNL list requested from [" << target_pubkey.substr(0, 10) << "]. Required unl hash:" << hash_bin2hex(required_unl).substr(0, 15);
    }

    /**
     * Perform unl syncing and serving.
    */
    void unl_syncer_loop()
    {
        util::mask_signal();

        std::cout << "unl sync: Worker started.\n";

        std::list<std::pair<std::string, p2p::unl_sync_request>> unl_requests;
        std::list<p2p::unl_sync_response> unl_responses;

        // Indicates whether any requests/responses were processed in the previous loop iteration.
        bool prev_processed = false;

        while (!sync_ctx.is_shutting_down)
        {
            // Wait a small delay if there were no requests/responses processed during previous iteration.
            if (!prev_processed)
                util::sleep(SYNCER_IDLE_WAIT);

            const std::string current_unl = get_hash();

            // Move over the collected sync items to the local lists.
            {
                std::scoped_lock<std::mutex>(sync_ctx.list_mutex);
                unl_requests.splice(unl_requests.end(), sync_ctx.collected_unl_sync_requests);
                unl_responses.splice(unl_responses.end(), sync_ctx.collected_unl_sync_responses);
            }

            prev_processed = !unl_requests.empty() || !unl_responses.empty();

            // Process any target unl sync activities.
            {
                std::scoped_lock<std::mutex> lock(sync_ctx.target_unl_mutex);

                if (!sync_ctx.target_unl.empty())
                {

                    // Scan any queued unl sync responses.
                    // Only process the first successful item which matches with our target unl.
                    for (const p2p::unl_sync_response &unl : unl_responses)
                    {
                        if (unl.requester_unl == sync_ctx.target_unl && verify_and_replace(unl.unl_list) != -1)
                        {
                            LOG_INFO << "unl sync: Sync complete. New unl:" << hash_bin2hex(sync_ctx.target_unl).substr(0, 15);
                            sync_ctx.target_unl.clear();
                            sync_ctx.is_syncing = false;
                            break;
                        }
                    }
                }

                unl_responses.clear();
            }

            // Serve any unl requests from other nodes.
            {
                std::shared_lock lock(unl_mutex);

                for (const auto &[session_id, unl_request] : unl_requests)
                {
                    // First check whether we are at the required unl state.
                    if (unl_request.required_unl != get_hash())
                        continue;

                    p2p::unl_sync_response resp;
                    resp.requester_unl = get_hash();
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

                unl_requests.clear();
            }
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

} // namespace unl
