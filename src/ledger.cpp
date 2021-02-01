#include "pchheader.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "p2p/p2p.hpp"
#include "msg/fbuf/common_helpers.hpp"
#include "msg/fbuf/ledger_helpers.hpp"
#include "msg/fbuf/p2pmsg_helpers.hpp"
#include "hplog.hpp"
#include "ledger.hpp"
#include "ledger/ledger_sample.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace ledger
{
    constexpr int FILE_PERMS = 0644;
    constexpr uint64_t MAX_LEDGER_SEQUENCE = 256; // Max ledger block count to keep.
    constexpr uint16_t SYNCER_IDLE_WAIT = 20;     // lcl syncer loop sleep time (milliseconds).

    // Max no. of repetitive reqeust resubmissions before abandoning the sync.
    constexpr uint16_t ABANDON_THRESHOLD = 10;

    // No. of milliseconds to wait before resubmitting a request.
    uint16_t REQUEST_RESUBMIT_TIMEOUT;

    ledger_context ctx;
    sync_context sync_ctx;
    bool init_success = false;

    /**
     * Retrieve ledger history information from persisted ledgers.
     */
    int init()
    {
        REQUEST_RESUBMIT_TIMEOUT = conf::cfg.contract.roundtime;

        // Filename list of the history folder.
        std::list<std::string> sorted_folder_entries = util::fetch_dir_entries(conf::ctx.hist_dir);
        // Sorting to make filenames in seq_no order.
        if (sort_lcl_filenames_and_validate(sorted_folder_entries) == -1)
        {
            return -1;
        }

        std::string previous_block_lcl;
        uint64_t previous_block_seq_no;
        // Get all records at lcl history direcory and find the last closed ledger.
        for (const auto &entry : sorted_folder_entries)
        {
            const std::string file_path = conf::ctx.hist_dir + "/" + entry;

            if (util::is_dir_exists(file_path))
            {
                LOG_ERROR << "Found directory " << entry << " in " << conf::ctx.hist_dir << ". There should be no folders in this directory.";
                return -1;
            }
            else
            {
                const std::string file_name(util::remove_file_extension(entry));

                uint64_t seq_no;
                std::string hash;
                if (extract_lcl(file_name, seq_no, hash) != -1)
                {
                    std::vector<uint8_t> buffer;
                    if (read_ledger(file_path, buffer) == -1)
                        return -1;

                    if (!msg::fbuf::ledger::verify_ledger_block_buffer(buffer.data(), buffer.size()))
                    {
                        LOG_ERROR << "Ledger data verification failed. " << file_name;
                        return -1;
                    }
                    if (!check_block_integrity(hash, buffer))
                    {
                        LOG_ERROR << "Ledger block integrity check failed. " << file_name;
                        return -1;
                    }

                    // Ledger integrity check.
                    if (!previous_block_lcl.empty())
                    {
                        const p2p::proposal proposal = msg::fbuf::ledger::create_proposal_from_ledger_block(buffer);
                        if ((seq_no - previous_block_seq_no != 1) && (previous_block_lcl != proposal.lcl))
                        {
                            LOG_ERROR << "Ledger block chain-link verification failed. " << file_name;
                            return -1;
                        }
                    }
                    previous_block_lcl = file_name;
                    previous_block_seq_no = seq_no;

                    ctx.cache.emplace(seq_no, std::move(file_name)); // cache -> [seq_no - hash]
                }
                else
                {
                    // lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
                    LOG_ERROR << "Invalid lcl file name: " << file_name;
                    return -1;
                }
            }
        }

        // Check if there is a saved lcl file -> if no send genesis lcl.
        if (ctx.cache.empty())
        {
            ctx.set_lcl(0, GENESIS_LEDGER);
        }
        else
        {
            const auto last_ledger = ctx.cache.rbegin();
            ctx.set_lcl(last_ledger->first, last_ledger->second);

            const uint64_t seq_no = ctx.get_seq_no();

            // Remove old ledgers that exceeds max sequence range.
            if (seq_no > MAX_LEDGER_SEQUENCE)
                remove_old_ledgers(seq_no - MAX_LEDGER_SEQUENCE);
        }

        sync_ctx.lcl_sync_thread = std::thread(lcl_syncer_loop);

        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            sync_ctx.is_shutting_down = true;
            sync_ctx.lcl_sync_thread.join();
        }
    }

    void set_sync_target(const std::string &target_lcl)
    {
        if (sync_ctx.is_shutting_down)
            return;

        // Validate target lcl format.
        uint64_t target_seq_no;
        std::string target_hash;
        if (extract_lcl(target_lcl, target_seq_no, target_hash) == -1)
        {
            LOG_ERROR << "lcl sync: Invalid target lcl " << target_seq_no;
            return;
        }

        {
            std::scoped_lock<std::mutex> lock(sync_ctx.target_lcl_mutex);
            if (sync_ctx.target_lcl == target_lcl)
                return;
            sync_ctx.target_lcl = target_lcl;
            sync_ctx.target_lcl_seq_no = target_seq_no;
            sync_ctx.target_requested_on = 0;
            sync_ctx.request_submissions = 0;
            sync_ctx.is_syncing = true;

            LOG_INFO << "lcl sync: Syncing for target:" << sync_ctx.target_lcl.substr(0, 15) << " (current:" << ctx.get_lcl().substr(0, 15) << ")";
        }
    }

    /**
     * Runs the lcl sync worker loop.
     */
    void lcl_syncer_loop()
    {
        util::mask_signal();

        LOG_INFO << "lcl sync: Worker started.";

        while (!sync_ctx.is_shutting_down)
        {
            // Indicates whether any requests/responses were processed in the loop iteration.
            bool processed = false;

            // Perform lcl sync activities.
            {
                std::scoped_lock<std::mutex> lock(sync_ctx.target_lcl_mutex);
                if (!sync_ctx.target_lcl.empty())
                    send_lcl_sync_request(); // Send lcl requests if needed (or abandon if sync timeout).

                // Process any history responses from other nodes.
                if (!sync_ctx.target_lcl.empty() && check_lcl_sync_responses() == 1)
                    processed = true;
            }

            // Serve any history requests from other nodes.
            if (check_lcl_sync_requests() == 1)
                processed = true;

            // Wait a small delay if there were no requests/responses processed during previous iteration.
            if (!processed)
                util::sleep(SYNCER_IDLE_WAIT);
        }

        LOG_INFO << "lcl sync: Worker stopped.";
    }

    /**
     * Submits/resubmits lcl history requests as needed. Abandons sync if threshold reached.
     */
    void send_lcl_sync_request()
    {
        // If target lcl is genesis lcl, Clear the ledger history and reset target sequence number.
        if (sync_ctx.target_lcl == GENESIS_LEDGER)
        {
            LOG_INFO << "lcl sync: Target is GENESIS. Clearing our history.";
            clear_ledger();
            sync_ctx.clear_target();
        }
        else
        {
            // Check whether we need to send any requests or abandon the sync due to timeout.
            const uint64_t time_now = util::get_epoch_milliseconds();
            if ((sync_ctx.target_requested_on == 0) ||                                // Initial request.
                (time_now - sync_ctx.target_requested_on) > REQUEST_RESUBMIT_TIMEOUT) // Request resubmission.
            {
                if (sync_ctx.request_submissions < ABANDON_THRESHOLD)
                {
                    // Before first request, if full history mode is not enabled check the target lcl seq no to see whether
                    // it's too far ahead. That means no one probably has our lcl in their ledgers. So we should clear our
                    // entire ledger history before requesting from peers.
                    if (sync_ctx.target_requested_on == 0 && !conf::cfg.node.full_history && sync_ctx.target_lcl_seq_no > (ctx.get_seq_no() + MAX_LEDGER_SEQUENCE))
                    {
                        LOG_INFO << "lcl sync: Target " << sync_ctx.target_lcl.substr(0, 15) << " is too far ahead. Clearing our history.";
                        clear_ledger();
                    }

                    send_ledger_history_request(ctx.get_lcl(), sync_ctx.target_lcl);
                    sync_ctx.target_requested_on = time_now;
                    sync_ctx.request_submissions++;
                }
                else
                {
                    LOG_INFO << "lcl sync: Resubmission threshold exceeded. Abandoning sync.";
                    sync_ctx.clear_target();
                }
            }
        }
    }

    /**
     * Processes any lcl responses we have received from other peers.
     * @return 0 if no respones were processed. 1 if at least one response was processed.
     */
    int check_lcl_sync_responses()
    {
        // Move over the collected responses to the local list.
        std::list<p2p::history_response> history_responses;
        {
            std::scoped_lock<std::mutex>(sync_ctx.list_mutex);
            history_responses.splice(history_responses.end(), sync_ctx.collected_history_responses);
        }

        const std::string current_lcl = ctx.get_lcl();

        // Scan any queued lcl history responses.
        // Only process the first successful item which matches with our current lcl.
        for (const p2p::history_response &hr : history_responses)
        {
            if (hr.requester_lcl == current_lcl)
            {
                std::string new_lcl;
                if (handle_ledger_history_response(hr, new_lcl) != -1)
                {
                    LOG_INFO << "lcl sync: Sync complete. New lcl:" << new_lcl.substr(0, 15);
                    sync_ctx.clear_target();

                    break;
                }
            }
        }

        return history_responses.empty() ? 0 : 1;
    }

    /**
     * Serves any lcl requests we have received from other peers.
     * @return 0 if no requests were served. 1 if at least one request was served.
     */
    int check_lcl_sync_requests()
    {
        // Move over the collected requests to the local list.
        std::list<std::pair<std::string, p2p::history_request>> history_requests;
        {
            std::scoped_lock<std::mutex>(sync_ctx.list_mutex);
            history_requests.splice(history_requests.end(), sync_ctx.collected_history_requests);
        }

        // Acquire lock so consensus does not update the ledger while we are reading the ledger.
        std::scoped_lock<std::mutex> ledger_lock(ctx.ledger_mutex);

        for (const auto &[session_id, hr] : history_requests)
        {
            // First check whether we have the required lcl available.
            if (!check_required_lcl_availability(hr.required_lcl))
                continue;

            p2p::history_response resp;
            if (ledger::retrieve_ledger_history(hr, resp) != -1)
            {
                flatbuffers::FlatBufferBuilder fbuf(1024);
                p2pmsg::create_msg_from_history_response(fbuf, resp);
                std::string_view msg = msg::fbuf::flatbuff_bytes_to_sv(fbuf.GetBufferPointer(), fbuf.GetSize());

                // Find the peer that we should send the history response to.
                std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
                const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

                if (peer_itr != p2p::ctx.peer_connections.end())
                {
                    comm::comm_session *session = peer_itr->second;
                    session->send(msg);
                }
            }
        }

        return history_requests.empty() ? 0 : 1;
    }

    /**
     * Returns the current top ledger seq no and lcl.
     */
    const std::pair<uint64_t, std::string> get_ledger_cache_top()
    {
        const auto latest_lcl_itr = ctx.cache.rbegin();

        if (latest_lcl_itr == ctx.cache.rend())
            return std::make_pair(0, GENESIS_LEDGER);
        else
            return std::make_pair(latest_lcl_itr->first, latest_lcl_itr->second);
    }

    /**
     * Create and save ledger from the given proposal message. Called by consensus.
     * @param proposal Consensus-reached Stage 3 proposal.
     * @param raw_inputs Raw inputs that are going to store.
     */
    int save_ledger(const p2p::proposal &proposal, const std::unordered_map<std::string, usr::raw_user_input> &raw_inputs)
    {
        // This is used as a sample to create ledger sqlite database,
        // Later this callee method can be called directly from consensus on ledger storage implementations. 
        ledger::ledger_sample::save_ledger(proposal);

        uint64_t seq_no = 0;
        std::string hash;
        if (extract_lcl(proposal.lcl, seq_no, hash) == -1)
        {
            // lcl records should follow [ledger sequnce numer]-[lcl hex] format.
            LOG_ERROR << "Invalid lcl name: " << proposal.lcl << " when saving ledger.";
            return -1;
        }

        seq_no++; // New lcl sequence number.

        // Serialize lcl using flatbuffer ledger block schema.
        flatbuffers::FlatBufferBuilder builder(1024);
        msg::fbuf::ledger::create_ledger_block_from_proposal(builder, proposal, seq_no);

        // Get binary hash of the serialized lcl.
        std::string_view ledger_str_buf = msg::fbuf::flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
        const std::string lcl_hash = crypto::get_hash(ledger_str_buf);

        // Get hex from binary hash.
        const std::string lcl_hash_hex = util::to_hex(lcl_hash);

        // Acquire lock so history request serving does not access the ledger while consensus is updating the ledger.
        std::scoped_lock<std::mutex> ledger_lock(ctx.ledger_mutex);

        // Construct lcl file name.
        // lcl file name should follow [ledger sequnce numer]-lcl[lcl hex] format.
        const std::string file_name = std::to_string(seq_no) + "-" + lcl_hash_hex;
        if (write_ledger(file_name, builder.GetBufferPointer(), builder.GetSize()) == -1)
            return -1;

        ctx.set_lcl(seq_no, file_name);

        ctx.cache.emplace(seq_no, std::move(file_name));

        // Write full history to the full history directory if full history mode is on.
        if (conf::cfg.node.full_history)
        {
            builder.Clear();
            msg::fbuf::ledger::create_full_history_block_from_raw_input_map(builder, raw_inputs);
            if (write_full_history(file_name, builder.GetBufferPointer(), builder.GetSize()) == -1)
                return -1;
        }

        //Remove old ledgers that exceeds max sequence range.
        if (seq_no > MAX_LEDGER_SEQUENCE)
            remove_old_ledgers(seq_no - MAX_LEDGER_SEQUENCE);

        return 0;
    }

    /**
     * Remove old ledgers that exceeds max sequence range from file system and ledger history cache.
     * @param led_seq_no minimum sequence number to be in history.
     */
    void remove_old_ledgers(const uint64_t led_seq_no)
    {
        // Remove old ledgers if full history mode is not enabled.
        if (!conf::cfg.node.full_history)
        {
            std::map<uint64_t, const std::string>::iterator itr;

            for (itr = ctx.cache.begin();
                 itr != ctx.cache.lower_bound(led_seq_no + 1);
                 itr++)
            {
                const std::string file_path = conf::ctx.hist_dir + "/" + itr->second + ".lcl";

                if (util::is_file_exists(file_path))
                    util::remove_file(file_path);
            }

            if (!ctx.cache.empty())
                ctx.cache.erase(ctx.cache.begin(), ctx.cache.lower_bound(led_seq_no + 1));
        }
    }

    /**
     * Clears out entire ledger history.
     */
    void clear_ledger()
    {
        util::clear_directory(conf::ctx.hist_dir);
        ctx.cache.clear();
        ctx.set_lcl(0, GENESIS_LEDGER);
    }

    /**
     * Reads the specified ledger entry.
     * @param file_path File path to read.
     * @param buffer Buffer to populate with file contents.
     * @return 0 on success. -1 on failure.
     */
    int read_ledger(std::string_view file_path, std::vector<uint8_t> &buffer)
    {
        const int fd = open(file_path.data(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening ledger file for read. " << file_path;
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error in ledger file stat. " << file_path;
            return -1;
        }

        buffer.resize(st.st_size);
        if (read(fd, buffer.data(), buffer.size()) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading ledger file. " << file_path;
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Write ledger to file system.
     * @param file_name current ledger sequence number.
     * @param ledger_raw raw lcl data.
     * @param ledger_size size of the raw lcl data.
     */
    int write_ledger(const std::string &file_name, const uint8_t *ledger_raw, const size_t ledger_size)
    {
        // Create file path to save ledger.
        // file name -> [ledger sequnce numer]-[lcl hex]

        const std::string file_path = conf::ctx.hist_dir + "/" + file_name + ".lcl";

        // Write ledger to file system
        const int fd = open(file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error creating ledger file. " << file_path;
            return -1;
        }

        if (write(fd, ledger_raw, ledger_size) == -1)
        {
            LOG_ERROR << errno << ": Error writing to new ledger file. " << file_path;
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Write full history to file system.
     * @param file_name current ledger sequence number.
     * @param full_history_raw raw full history data.
     * @param full_history_size size of the raw full history data.
     */
    int write_full_history(const std::string &file_name, const uint8_t *full_history_raw, const size_t full_history_size)
    {
        // Create file path to save full history.
        // file name -> [ledger sequnce numer]-[lcl hex]

        const std::string file_path = conf::ctx.full_hist_dir + "/" + file_name + ".flcl";

        // Write full history to file system
        const int fd = open(file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error creating full history file. " << file_path;
            return -1;
        }

        if (write(fd, full_history_raw, full_history_size) == -1)
        {
            LOG_ERROR << errno << ": Error writing to new full history file. " << file_path;
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Delete ledger from file system.
     * @param file_name name of ledger to be deleted.
     */
    void remove_ledger(const std::string &file_name)
    {
        std::string file_path;
        file_path.reserve(conf::ctx.hist_dir.size() + file_name.size() + 5);
        file_path.append(conf::ctx.hist_dir)
            .append("/")
            .append(file_name)
            .append(".lcl");
        util::remove_file(file_path);

        // Removing full history if exists.
        file_path.clear();
        file_path.reserve(conf::ctx.full_hist_dir.size() + file_name.size() + 6);
        file_path.append(conf::ctx.full_hist_dir)
            .append("/")
            .append(file_name)
            .append(".flcl");
        if (util::is_file_exists(file_path))
            util::remove_file(file_path);
    }

    /**
     * Create and send ledger history request to random node from unl list.
     * @param current_lcl Current lcl.
     * @param required_lcl Required lcl.
     */
    void send_ledger_history_request(std::string_view current_lcl, std::string_view required_lcl)
    {
        p2p::history_request hr;
        hr.required_lcl = required_lcl;
        hr.requester_lcl = current_lcl;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_history_request(fbuf, hr);

        std::string target_pubkey;
        p2p::send_message_to_random_peer(fbuf, target_pubkey);

        LOG_DEBUG << "Ledger history requested from [" << target_pubkey.substr(0, 10) << "]. Required lcl:" << required_lcl.substr(0, 15);
    }

    /**
     * Check requested lcl is in node's lcl history cache.
     * @param hr lcl history request information.
     * @return true if requested lcl is in lcl history cache.
     */
    bool check_required_lcl_availability(const std::string &required_lcl)
    {
        uint64_t req_seq_no = 0;
        std::string hash;
        if (extract_lcl(required_lcl, req_seq_no, hash) == -1)
        {
            LOG_DEBUG << "Required lcl parse error " << required_lcl;
            return -1;
        }

        if (req_seq_no > 0)
        {
            const auto itr = ctx.cache.find(req_seq_no);
            if (itr == ctx.cache.end())
            {
                LOG_DEBUG << "Required lcl seq no peer asked for is not in our lcl cache. " << required_lcl;
                // Either this node is also not in consesnsus ledger or other node requesting a lcl that is older than node's current
                // minimum lcl sequence becuase of maximum ledger history range.
                return false;
            }
            else if (itr->second != required_lcl)
            {
                LOG_DEBUG << "Required lcl peer asked for is not in our lcl cache. " << required_lcl;
                // Either this node or requesting node is in a fork condition.
                return false;
            }
        }
        else
        {
            return false; // Very rare case: Peer asking for the genisis lcl.
        }

        return true;
    }

    /**
     * Retrieve lcl(last closed ledger) information from ledger history.
     * @param hr lcl history request information.
     * @param history_response Ledger history response to populate requested ledger details
     * @return 0 on success. -1 on failure.
     */
    int retrieve_ledger_history(const p2p::history_request &hr, p2p::history_response &history_response)
    {
        uint64_t min_seq_no = 0;
        std::string hash;
        if (extract_lcl(hr.requester_lcl, min_seq_no, hash) == -1)
        {
            LOG_DEBUG << "lcl serve: Invalid request. Requester lcl invalid:" << hr.requester_lcl;
            return -1;
        }

        // We put the requester's own lcl back in the response so they can validate the liveliness of the response.
        history_response.requester_lcl = hr.requester_lcl;

        if (min_seq_no > 0)
        {
            const auto itr = ctx.cache.find(min_seq_no);
            if (itr != ctx.cache.end()) // Requested minimum lcl was found in our lcl history cache
            {
                // Check whether requested minimum lcl hash is same as this node's.
                // Evenhough sequence number are same, lcl hash can be changed if one of node is in a fork condition.
                if (hr.requester_lcl != itr->second)
                {
                    LOG_DEBUG << "lcl serve: Invalid minimum ledger. Requester lcl:" << hr.requester_lcl << " Node lcl:" << itr->second;
                    history_response.error = p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER;
                    return 0;
                }

                min_seq_no = itr->first;
            }
            else if (min_seq_no > ctx.cache.rbegin()->first) //Recieved minimum lcl sequence is ahead of node's lcl sequence.
            {
                LOG_DEBUG << "lcl serve: Invalid minimum ledger. Requester lcl " << hr.requester_lcl << " is ahead of us.";
                history_response.error = p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER;
                return 0;
            }
            else
            {
                LOG_DEBUG << "lcl serve: Requester lcl is not in our lcl cache. Sending our entire history.";
                min_seq_no = ctx.cache.begin()->first;
            }
        }
        else
        {
            LOG_DEBUG << "lcl serve: Requester lcl is GENSIS. Sending our entire history.";
            min_seq_no = ctx.cache.begin()->first;
        }

        //copy current history cache.
        std::map<uint64_t, const std::string> led_cache = ctx.cache;

        //filter out cache and get raw files here.
        led_cache.erase(
            led_cache.begin(),
            led_cache.lower_bound(min_seq_no));

        //Get raw content of lcls that going to be send.
        for (const auto &[seq_no, lcl] : led_cache)
        {
            p2p::history_ledger_block ledger_block;
            ledger_block.lcl = lcl;

            // Read lcl file.
            const std::string file_path = conf::ctx.hist_dir + "/" + lcl + ".lcl";
            if (read_ledger(file_path, ledger_block.block_buffer) == -1)
            {
                LOG_DEBUG << "lcl serve: Error when reading ledger file.";
                return -1;
            }

            history_response.hist_ledger_blocks.emplace(seq_no, std::move(ledger_block));
        }

        return 0;
    }

    /**
     * Handle recieved ledger history response.
     * @param hr lcl history request information.
     * @return 0 on successful lcl update. -1 on failure.
     */
    int handle_ledger_history_response(const p2p::history_response &hr, std::string &new_lcl)
    {
        if (hr.error == p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER)
        {
            // This means we are in a fork ledger. Remove/rollback current top ledger.
            // Basically in the long run we'll rolback one by one untill we catch up to valid minimum ledger.
            remove_ledger(ctx.get_lcl());
            ctx.cache.erase(ctx.cache.rbegin()->first);

            const auto [seq_no, lcl] = get_ledger_cache_top();
            ctx.set_lcl(seq_no, lcl);

            new_lcl = lcl;
            LOG_INFO << "lcl sync: Fork detected. Removed last ledger. New lcl:" << lcl.substr(0, 15);
            return 0;
        }
        else
        {
            // Check whether recieved lcl history contains the current lcl node required.
            bool contains_requested_lcl = false;
            for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
            {
                if (sync_ctx.target_lcl == ledger.lcl)
                {
                    contains_requested_lcl = true;
                    break;
                }
            }

            if (!contains_requested_lcl)
            {
                LOG_INFO << "lcl sync: Peer sent us a history response but not containing the lcl we asked for.";
                return -1;
            }

            // Check integrity of recieved lcl list.
            // By checking recieved lcl hashes matches lcl content by applying hashing for each raw content.
            std::string previous_history_block_lcl;
            uint64_t previous_history_block_seq_no;
            for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
            {
                // Individually check each ledger entry's integrity before the chain check.
                uint64_t lcl_seq_no;
                std::string lcl_hash;
                if (extract_lcl(ledger.lcl, lcl_seq_no, lcl_hash) == -1)
                {
                    LOG_INFO << "lcl sync: Error when parsing lcl " << ledger.lcl;
                    return -1;
                }

                if (!check_block_integrity(lcl_hash, ledger.block_buffer))
                {
                    LOG_INFO << "lcl sync: Peer sent us a history response but the ledger data does not match the hashes.";
                    // todo: we should penalize peer who sent this.
                    return -1;
                }

                // Ledger chain integrity check.
                if (!previous_history_block_lcl.empty())
                {
                    const p2p::proposal proposal = msg::fbuf::ledger::create_proposal_from_ledger_block(ledger.block_buffer);
                    if ((seq_no - previous_history_block_seq_no != 1) && (previous_history_block_lcl != proposal.lcl))
                    {
                        LOG_INFO << "Ledger block chain-link verification failed. " << ledger.lcl;
                        return -1;
                    }
                }
                previous_history_block_lcl = ledger.lcl;
                previous_history_block_seq_no = seq_no;
            }
        }

        // Performing ledger history joining check.
        if (!ctx.cache.empty())
        {
            const auto history_itr = hr.hist_ledger_blocks.begin();
            const p2p::proposal history_first_proposal = msg::fbuf::ledger::create_proposal_from_ledger_block(history_itr->second.block_buffer);

            // Removing ledger blocks upto the received histroy response starting point.
            const uint64_t joining_seq_no = history_itr->first;
            if (ctx.cache.count(joining_seq_no) == 1)
            {
                // If cache ledger and history ledger are overlapping, remove blocks from end until the
                // cache end at the state where history ledger can be straightly joined.
                auto it = ctx.cache.rbegin();
                while (it != ctx.cache.rend() && it->first >= joining_seq_no)
                {
                    remove_ledger(it->second);

                    // Erase and advance the reverse iterator.
                    ctx.cache.erase((--it.base()));
                }

                auto &[cache_seq_no, cache_lcl] = get_ledger_cache_top();
                ctx.set_lcl(cache_seq_no, cache_lcl);

                // Comparing the sequence number and the lcl to validate the joining point.
                if ((history_itr->first - cache_seq_no != 1) || (history_first_proposal.lcl != cache_lcl))
                {
                    LOG_ERROR << "lcl sync: Ledger integrity check at history joining point failed.";
                    return -1;
                }
            }
        }

        // Execution to here means the history data sent checks out.
        // Save recieved lcl in file system and update lcl history cache.
        for (auto &[seq_no, ledger] : hr.hist_ledger_blocks)
        {
            write_ledger(ledger.lcl, ledger.block_buffer.data(), ledger.block_buffer.size());
            ctx.cache.emplace(seq_no, ledger.lcl);
        }

        const auto [seq_no, lcl] = get_ledger_cache_top();
        ctx.set_lcl(seq_no, lcl);

        new_lcl = lcl;
        return 0;
    }
    /**
     * Check the integrity of the given ledger.
     * @param supplied_hash supplied hash hex of the ledger block.
     * @param raw_ledger ledger.
     * @return true if the integrity check passes and false otherwise.
     */
    bool check_block_integrity(std::string_view supplied_hash, const std::vector<uint8_t> &block_buffer)
    {
        // Get binary hash of the serialized lcl.
        const std::string binary_block_hash = crypto::get_hash(block_buffer.data(), block_buffer.size());

        // Get hex from binary hash.
        const std::string block_hash = util::to_hex(binary_block_hash);

        return block_hash == supplied_hash;
    }

    /**
     * Sorting given lcl filename list in sequence number order and validate filenames.
     * @param list List of lcl filenames.
     * @return 0 if success and -1 on error.
    */
    int sort_lcl_filenames_and_validate(std::list<std::string> &list)
    {
        try
        {
            list.sort([](std::string &a, std::string &b) {
                uint64_t seq_no_a, seq_no_b;
                if (util::stoull(a.substr(0, a.find("-")), seq_no_a) == -1)
                {
                    throw "Lcl file parsing error in file " + a + " in " + conf::ctx.hist_dir;
                }
                if (util::stoull(b.substr(0, b.find("-")), seq_no_b) == -1)
                {
                    throw "Lcl file parsing error in file " + b + " in " + conf::ctx.hist_dir;
                }
                const std::string_view extension_a = util::fetch_file_extension(a);
                if (extension_a != ".lcl")
                {
                    throw "Found invalid file extension: " + std::string(extension_a) + " for lcl file " + a + " in " + conf::ctx.hist_dir;
                }
                const std::string_view extension_b = util::fetch_file_extension(b);
                if (extension_b != ".lcl")
                {
                    throw "Found invalid file extension: " + std::string(extension_b) + " for lcl file " + b + " in " + conf::ctx.hist_dir;
                }
                return seq_no_a < seq_no_b;
            });
            return 0;
        }
        catch (std::string message)
        {
            LOG_ERROR << message;
            return -1;
        }
    }

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash)
    {
        if (lcl == GENESIS_LEDGER)
        {
            seq_no = 0;
            hash = lcl.substr(2);
            return 0;
        }

        const size_t pos = lcl.find("-");
        if (pos == std::string::npos)
            return -1;

        if (util::stoull(lcl.substr(0, pos), seq_no) == -1)
            return -1;

        hash = lcl.substr(pos + 1);
        if (hash.size() != 64)
            return -1;

        return 0;
    }

} // namespace ledger