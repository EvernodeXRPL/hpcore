#include "log_sync.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../ledger/ledger.hpp"
#include "../msg/fbuf/p2pmsg_conversion.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;
namespace sc::log_sync
{
    constexpr int FILE_PERMS = 0644;
    constexpr uint16_t SYNCER_IDLE_WAIT = 20; // lcl syncer loop sleep time (milliseconds).

    // Max no. of repetitive reqeust resubmissions before abandoning the sync.
    constexpr uint16_t ABANDON_THRESHOLD = 10;

    // No. of milliseconds to wait before resubmitting a request.
    uint16_t REQUEST_RESUBMIT_TIMEOUT;

    sync_context sync_ctx;
    bool init_success = false;

    /**
     * Retrieve ledger history information from persisted ledgers.
     */
    int init()
    {
        REQUEST_RESUBMIT_TIMEOUT = conf::cfg.contract.roundtime;

        sync_ctx.log_record_sync_thread = std::thread(log_record_syncer_loop);

        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            sync_ctx.is_shutting_down = true;
            sync_ctx.log_record_sync_thread.join();
        }
    }

    void set_sync_target(const p2p::sequence_hash target)
    {
        {
            std::scoped_lock lock(sync_ctx.target_log_record_mutex);
            if (sync_ctx.is_shutting_down || (sync_ctx.is_syncing && sync_ctx.target_log_record == target))
                return;

            sync_ctx.target_log_record = target;
        }

        if (get_verified_min_record() == -1)
            return;

        LOG_INFO << "target: " << target;

        sync_ctx.target_requested_on = 0;
        sync_ctx.request_submissions = 0;
        sync_ctx.is_syncing = true;
    }

    /**
     * Runs the lcl sync worker loop.
     */
    void log_record_syncer_loop()
    {
        util::mask_signal();

        LOG_INFO << "log record sync: Worker started.";

        while (!sync_ctx.is_shutting_down)
        {
            // Indicates whether any requests/responses were processed in the loop iteration.
            bool processed = false;

            // Perform lcl sync activities.
            {
                std::scoped_lock<std::mutex> lock(sync_ctx.target_log_record_mutex);
                if (!sync_ctx.target_log_record.empty())
                    send_log_record_sync_request(); // Send lcl requests if needed (or abandon if sync timeout).

                // Process any history responses from other nodes.
                if (!sync_ctx.target_log_record.empty() && check_log_record_sync_responses() == 1)
                    processed = true;
            }

            // Serve any history requests from other nodes.
            if (check_log_record_sync_requests() == 1)
                processed = true;

            // Wait a small delay if there were no requests/responses processed during previous iteration.
            if (!processed)
                util::sleep(SYNCER_IDLE_WAIT);
        }

        LOG_INFO << "log record sync: Worker stopped.";
    }

    /**
     * Submits/resubmits lcl history requests as needed. Abandons sync if threshold reached.
     */
    void send_log_record_sync_request()
    {
        // Check whether we need to send any requests or abandon the sync due to timeout.
        const uint64_t time_now = util::get_epoch_milliseconds();
        if ((sync_ctx.target_requested_on == 0) ||                                // Initial request.
            (time_now - sync_ctx.target_requested_on) > REQUEST_RESUBMIT_TIMEOUT) // Request resubmission.
        {
            if (sync_ctx.request_submissions < ABANDON_THRESHOLD)
            {
                flatbuffers::FlatBufferBuilder fbuf;
                p2pmsg::create_msg_from_log_record_request(fbuf, {sync_ctx.target_log_record, sync_ctx.min_log_record});
                std::string target_pubkey;
                p2p::send_message_to_random_peer(fbuf, target_pubkey, true);
                if (!target_pubkey.empty())
                {
                    LOG_WARNING << "log sync: Requested log record from: " << target_pubkey.substr(2, 10);
                    sync_ctx.target_requested_on = time_now;
                    sync_ctx.request_submissions++;
                }
            }
            else
            {
                LOG_INFO << "log sync: Resubmission threshold exceeded. Abandoning sync.";
                sync_ctx.clear_target();
            }
        }
    }

    /**
     * Processes any lcl responses we have received from other peers.
     * @return 0 if no respones were processed. 1 if at least one response was processed.
     */
    int check_log_record_sync_responses()
    {
        // Move over the collected responses to the local list.
        std::list<std::pair<std::string, p2p::log_record_response>> log_record_responses;

        {
            std::scoped_lock lock(p2p::ctx.collected_msgs.log_record_response_mutex);

            // Move collected hpfs responses over to local candidate responses list.
            if (!p2p::ctx.collected_msgs.log_record_responses.empty())
                log_record_responses.splice(log_record_responses.end(), p2p::ctx.collected_msgs.log_record_responses);
        }

        // const std::string current_lcl = ctx.get_lcl();

        // // Scan any queued lcl history responses.
        // // Only process the first successful item which matches with our current lcl.
        // for (const p2p::history_response &hr : history_responses)
        // {
        //     if (hr.requester_lcl == current_lcl)
        //     {
        //         std::string new_lcl;
        //         if (handle_ledger_history_response(hr, new_lcl) != -1)
        //         {
        //             LOG_INFO << "lcl sync: Sync complete. New lcl:" << new_lcl.substr(0, 15);
        //             sync_ctx.clear_target();

        //             break;
        //         }
        //     }
        // }

        return log_record_responses.empty() ? 0 : 1;
    }

    /**
     * Serves any lcl requests we have received from other peers.
     * @return 0 if no requests were served. 1 if at least one request was served.
     */
    int check_log_record_sync_requests()
    {
        // // Move over the collected requests to the local list.
        std::list<std::pair<std::string, p2p::log_record_request>> log_record_requests;

        {
            std::scoped_lock lock(p2p::ctx.collected_msgs.log_record_request_mutex);

            // Move collected hpfs responses over to local candidate responses list.
            if (!p2p::ctx.collected_msgs.log_record_requests.empty())
                log_record_requests.splice(log_record_requests.end(), p2p::ctx.collected_msgs.log_record_requests);
        }

        // util::h32 root_hash;
        // if (ledger::get_root_hash_from_ledger(root_hash, sync_ctx.target_log_record.seq_no) == -1)
        //     LOG_ERROR << "error getting root hash from ledger for: " << std::to_string(sync_ctx.target_log_record.seq_no);

        // LOG_WARNING << "root hash for " << std::to_string(sync_ctx.target_log_record.seq_no) << ": " << root_hash;

        // // Acquire lock so consensus does not update the ledger while we are reading the ledger.
        // std::scoped_lock<std::mutex> ledger_lock(ctx.ledger_mutex);

        for (const auto &[session_id, lr] : log_record_requests)
        {

            // // First check whether we have the required lcl available.
            // if (!check_required_log_record_availability(hr.required_lcl))
            //     continue;

            // p2p::history_response resp;
            // if (ledger::retrieve_ledger_history(hr, resp) != -1)
            // {
            //     flatbuffers::FlatBufferBuilder fbuf(1024);
            //     p2pmsg::create_msg_from_history_response(fbuf, resp);
            //     std::string_view msg = msg::fbuf::flatbuff_bytes_to_sv(fbuf.GetBufferPointer(), fbuf.GetSize());

            //     // Find the peer that we should send the history response to.
            //     std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
            //     const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

            //     if (peer_itr != p2p::ctx.peer_connections.end())
            //     {
            //         comm::comm_session *session = peer_itr->second;
            //         session->send(msg);
            //     }
            // }
            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2p::log_record_response resp;
            resp.max_record_id = lr.target_record_id;
            resp.min_record_id = lr.min_record_id;
            resp.log_records = std::vector<p2p::log_record>();
            p2pmsg::create_msg_from_log_record_response(fbuf, resp);
            std::string_view msg = std::string_view(reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            // Find the peer that we should send the history response to.
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
            const auto peer_itr = p2p::ctx.peer_connections.find(util::to_bin(session_id));

            if (peer_itr != p2p::ctx.peer_connections.end())
            {
                comm::comm_session *session = peer_itr->second;
                session->send(msg);
            }
        }

        return log_record_requests.empty() ? 0 : 1;
    }

    /**
     * Check requested lcl is in node's lcl history cache.
     * @param hr lcl history request information.
     * @return true if requested lcl is in lcl history cache.
     */
    bool check_required_log_record_availability(const p2p::sequence_hash &min_log_record)
    {
        return true;
    }

    /**
     * Handle recieved ledger history response.
     * @param hr lcl history request information.
     * @return 0 on successful lcl update. -1 on failure.
     */
    int handle_ledger_history_response(const p2p::log_record_response &hr, std::string &new_lcl)
    {
        // if (hr.error == p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER)
        // {
        //     // This means we are in a fork ledger. Remove/rollback current top ledger.
        //     // Basically in the long run we'll rolback one by one untill we catch up to valid minimum ledger.
        //     remove_ledger(ctx.get_lcl());
        //     ctx.cache.erase(ctx.cache.rbegin()->first);

        //     const auto [seq_no, lcl] = get_ledger_cache_top();
        //     ctx.set_lcl(seq_no, lcl);

        //     new_lcl = lcl;
        //     LOG_INFO << "lcl sync: Fork detected. Removed last ledger. New lcl:" << lcl.substr(0, 15);
        //     return 0;
        // }
        // else
        // {
        //     // Check whether recieved lcl history contains the current lcl node required.
        //     bool contains_requested_lcl = false;
        //     for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
        //     {
        //         if (sync_ctx.target_lcl == ledger.lcl)
        //         {
        //             contains_requested_lcl = true;
        //             break;
        //         }
        //     }

        //     if (!contains_requested_lcl)
        //     {
        //         LOG_INFO << "lcl sync: Peer sent us a history response but not containing the lcl we asked for.";
        //         return -1;
        //     }

        //     // Check integrity of recieved lcl list.
        //     // By checking recieved lcl hashes matches lcl content by applying hashing for each raw content.
        //     std::string previous_history_block_lcl;
        //     uint64_t previous_history_block_seq_no;
        //     for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
        //     {
        //         // Individually check each ledger entry's integrity before the chain check.
        //         uint64_t lcl_seq_no;
        //         std::string lcl_hash;
        //         if (extract_lcl(ledger.lcl, lcl_seq_no, lcl_hash) == -1)
        //         {
        //             LOG_INFO << "lcl sync: Error when parsing lcl " << ledger.lcl;
        //             return -1;
        //         }

        //         if (!check_block_integrity(lcl_hash, ledger.block_buffer))
        //         {
        //             LOG_INFO << "lcl sync: Peer sent us a history response but the ledger data does not match the hashes.";
        //             // todo: we should penalize peer who sent this.
        //             return -1;
        //         }

        //         // Ledger chain integrity check.
        //         if (!previous_history_block_lcl.empty())
        //         {
        //             const p2p::proposal proposal = msg::fbuf::ledger::create_proposal_from_ledger_block(ledger.block_buffer);
        //             if ((seq_no - previous_history_block_seq_no != 1) && (previous_history_block_lcl != proposal.lcl))
        //             {
        //                 LOG_INFO << "Ledger block chain-link verification failed. " << ledger.lcl;
        //                 return -1;
        //             }
        //         }
        //         previous_history_block_lcl = ledger.lcl;
        //         previous_history_block_seq_no = seq_no;
        //     }
        // }

        // // Performing ledger history joining check.
        // if (!ctx.cache.empty())
        // {
        //     const auto history_itr = hr.hist_ledger_blocks.begin();
        //     const p2p::proposal history_first_proposal = msg::fbuf::ledger::create_proposal_from_ledger_block(history_itr->second.block_buffer);

        //     // Removing ledger blocks upto the received histroy response starting point.
        //     const uint64_t joining_seq_no = history_itr->first;
        //     if (ctx.cache.count(joining_seq_no) == 1)
        //     {
        //         // If cache ledger and history ledger are overlapping, remove blocks from end until the
        //         // cache end at the state where history ledger can be straightly joined.
        //         auto it = ctx.cache.rbegin();
        //         while (it != ctx.cache.rend() && it->first >= joining_seq_no)
        //         {
        //             remove_ledger(it->second);

        //             // Erase and advance the reverse iterator.
        //             ctx.cache.erase((--it.base()));
        //         }

        //         auto &[cache_seq_no, cache_lcl] = get_ledger_cache_top();
        //         ctx.set_lcl(cache_seq_no, cache_lcl);

        //         // Comparing the sequence number and the lcl to validate the joining point.
        //         if ((history_itr->first - cache_seq_no != 1) || (history_first_proposal.lcl != cache_lcl))
        //         {
        //             LOG_ERROR << "lcl sync: Ledger integrity check at history joining point failed.";
        //             return -1;
        //         }
        //     }
        // }

        // // Execution to here means the history data sent checks out.
        // // Save recieved lcl in file system and update lcl history cache.
        // for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
        // {
        //     write_ledger(ledger.lcl, ledger.block_buffer.data(), ledger.block_buffer.size());
        //     ctx.cache.emplace(seq_no, ledger.lcl);
        // }

        // const auto [seq_no, lcl] = get_ledger_cache_top();
        // ctx.set_lcl(seq_no, lcl);

        // new_lcl = lcl;
        return 0;
    }

    int get_verified_min_record()
    {
        std::scoped_lock<std::mutex> lock(sync_ctx.min_log_record_mutex);
        // Represent the very first log record corresponding to the first sequence number;
        sync_ctx.min_log_record = {1, util::h32_empty};

        return 0;
    }

} // namespace ledger