#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../ledger.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../hpfs/hpfs.hpp"
#include "../hpfs/h32.hpp"
#include "state_sync.hpp"
#include "state_common.hpp"

namespace state_sync
{
    // Idle loop sleep time  (milliseconds).
    constexpr uint16_t IDLE_WAIT = 40;

    // Max number of requests that can be awaiting response at any given time.
    constexpr uint16_t MAX_AWAITING_REQUESTS = 4;

    // Request loop sleep time (milliseconds).
    constexpr uint16_t REQUEST_LOOP_WAIT = 10;

    // Max no. of repetitive reqeust resubmissions before abandoning the sync.
    constexpr uint16_t ABANDON_THRESHOLD = 20;

    constexpr int FILE_PERMS = 0644;

    // No. of milliseconds to wait before resubmitting a request.
    uint16_t REQUEST_RESUBMIT_TIMEOUT;
    sync_context ctx;
    bool init_success = false;

    int init()
    {
        REQUEST_RESUBMIT_TIMEOUT = state_common::get_request_resubmit_timeout();
        ctx.target_state = hpfs::h32_empty;
        ctx.state_sync_thread = std::thread(state_syncer_loop);
        ctx.hpfs_mount_dir = conf::ctx.state_rw_dir;
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            ctx.is_syncing = false;
            ctx.is_shutting_down = true;
            ctx.state_sync_thread.join();
        }
    }

    /**
     * Sets a new target state for the syncing process.
     * @param target_state The target state which we should sync towards.
     * @param completion_callback The callback function to call upon state sync completion.
     */
    void set_target(const hpfs::h32 target_state)
    {
        std::unique_lock lock(ctx.target_state_mutex);

        // Do not do anything if we are already syncing towards the specified target state.
        if (ctx.is_shutting_down || (ctx.is_syncing && ctx.target_state == target_state))
            return;

        ctx.target_state = target_state;
        ctx.is_syncing = true;
    }

    /**
     * Runs the state sync worker loop.
     */
    void state_syncer_loop()
    {
        util::mask_signal();

        LOG_INFO << "State sync: Worker started.";

        while (!ctx.is_shutting_down)
        {
            util::sleep(IDLE_WAIT);

            // Keep idling if we are not doing any sync activity.
            {
                std::shared_lock lock(ctx.target_state_mutex);
                if (!ctx.is_syncing)
                    continue;

                LOG_INFO << "State sync: Starting sync for target state: " << ctx.target_state;
            }

            if (hpfs::start_fs_session(ctx.hpfs_mount_dir) != -1)
            {
                while (!ctx.is_shutting_down)
                {
                    hpfs::h32 new_state = hpfs::h32_empty;
                    const int result = request_loop(ctx.target_state, new_state);

                    if (result == -1 || ctx.is_shutting_down)
                        break;

                    ctx.pending_requests.clear();
                    ctx.candidate_state_responses.clear();
                    ctx.submitted_requests.clear();

                    {
                        std::shared_lock lock(ctx.target_state_mutex);

                        if (new_state == ctx.target_state)
                        {
                            LOG_INFO << "State sync: Target state achieved: " << new_state;
                            break;
                        }
                        else
                        {
                            LOG_INFO << "State sync: Continuing sync for new target: " << ctx.target_state;
                            continue;
                        }
                    }
                }

                hpfs::stop_fs_session(ctx.hpfs_mount_dir);
            }
            else
            {
                LOG_ERROR << "State sync: Failed to start hpfs rw session";
            }

            std::unique_lock lock(ctx.target_state_mutex);
            ctx.target_state = hpfs::h32_empty;
            ctx.is_syncing = false;
        }

        LOG_INFO << "State sync: Worker stopped.";
    }

    int request_loop(const hpfs::h32 current_target, hpfs::h32 &updated_state)
    {
        std::string lcl = ledger::ctx.get_lcl();

        // Indicates whether any responses were processed in the previous loop iteration.
        bool prev_responses_processed = false;

        // No. of repetitive resubmissions so far. (This is reset whenever we receive a state response)
        uint16_t resubmissions_count = 0;

        // Send the initial root state request.
        submit_request(backlog_item{BACKLOG_ITEM_TYPE::DIR, "/", -1, current_target}, lcl);

        while (!should_stop_request_loop(current_target))
        {
            // Wait a small delay if there were no responses processed during previous iteration.
            if (!prev_responses_processed)
                util::sleep(REQUEST_LOOP_WAIT);

            // Get current lcl.
            std::string lcl = ledger::ctx.get_lcl();

            {
                std::scoped_lock lock(p2p::ctx.collected_msgs.state_responses_mutex);

                // Move collected state responses over to local candidate responses list.
                if (!p2p::ctx.collected_msgs.state_responses.empty())
                    ctx.candidate_state_responses.splice(ctx.candidate_state_responses.end(), p2p::ctx.collected_msgs.state_responses);
            }

            prev_responses_processed = !ctx.candidate_state_responses.empty();

            // Reset resubmissions counter whenever we have a resposne.
            if (!ctx.candidate_state_responses.empty())
                resubmissions_count = 0;

            for (auto &response : ctx.candidate_state_responses)
            {
                if (should_stop_request_loop(current_target))
                    return 0;

                LOG_DEBUG << "State sync: Processing state response from [" << response.first.substr(2, 10) << "]";

                const msg::fbuf::p2pmsg::Content *content = msg::fbuf::p2pmsg::GetContent(response.second.data());
                const msg::fbuf::p2pmsg::State_Response_Message *resp_msg = content->message_as_State_Response_Message();

                // Check whether we are actually waiting for this response. If not, ignore it.
                std::string_view hash = msg::fbuf::flatbuff_bytes_to_sv(resp_msg->hash());
                std::string_view vpath = msg::fbuf::flatbuff_str_to_sv(resp_msg->path());

                const std::string key = std::string(vpath).append(hash);
                const auto pending_resp_itr = ctx.submitted_requests.find(key);
                if (pending_resp_itr == ctx.submitted_requests.end())
                {
                    LOG_DEBUG << "State sync: Skipping state response due to hash mismatch.";
                    continue;
                }

                // Process the message based on response type.
                const msg::fbuf::p2pmsg::State_Response msg_type = resp_msg->state_response_type();

                if (msg_type == msg::fbuf::p2pmsg::State_Response_Fs_Entry_Response)
                {
                    const msg::fbuf::p2pmsg::Fs_Entry_Response *fs_resp = resp_msg->state_response_as_Fs_Entry_Response();

                    // Get fs entries we have received.
                    std::unordered_map<std::string, p2p::state_fs_hash_entry> peer_fs_entry_map;
                    msg::fbuf::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(peer_fs_entry_map, fs_resp->entries());

                    // Validate received fs data against the hash.
                    if (!validate_fs_entry_hash(vpath, hash, peer_fs_entry_map))
                    {
                        LOG_INFO << "State sync: Skipping state response due to fs entry hash mismatch.";
                        continue;
                    }

                    handle_fs_entry_response(vpath, peer_fs_entry_map);
                }
                else if (msg_type == msg::fbuf::p2pmsg::State_Response_File_HashMap_Response)
                {
                    const msg::fbuf::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();

                    // File block hashes we received from the peer.
                    const hpfs::h32 *peer_hashes = reinterpret_cast<const hpfs::h32 *>(file_resp->hash_map()->data());
                    const size_t peer_hash_count = file_resp->hash_map()->size() / sizeof(hpfs::h32);

                    // Validate received hashmap against the hash.
                    if (!validate_file_hashmap_hash(vpath, hash, peer_hashes, peer_hash_count))
                    {
                        LOG_INFO << "State sync: Skipping state response due to file hashmap hash mismatch.";
                        continue;
                    }

                    handle_file_hashmap_response(vpath, peer_hashes, peer_hash_count, file_resp->file_length());
                }
                else if (msg_type == msg::fbuf::p2pmsg::State_Response_Block_Response)
                {
                    const msg::fbuf::p2pmsg::Block_Response *block_resp = resp_msg->state_response_as_Block_Response();

                    // Get the file path of the block data we have received.
                    const uint32_t block_id = block_resp->block_id();
                    std::string_view buf = msg::fbuf::flatbuff_bytes_to_sv(block_resp->data());

                    // Validate received block data against the hash.
                    if (!validate_file_block_hash(hash, block_id, buf))
                    {
                        LOG_INFO << "State sync: Skipping state response due to file block hash mismatch.";
                        continue;
                    }

                    handle_file_block_response(vpath, block_id, buf);
                }

                // Now that we have received matching hash and handled it, remove it from the waiting list.
                ctx.submitted_requests.erase(pending_resp_itr);

                // After handling each response, check whether we have reached target state.
                if (hpfs::get_hash(updated_state, ctx.hpfs_mount_dir, "/") < 1)
                {
                    LOG_ERROR << "State sync: exiting due to hash check error.";
                    return -1;
                }

                // Update the central state tracker.
                state_common::ctx.set_state(updated_state);

                LOG_DEBUG << "State sync: current:" << updated_state << " | target:" << current_target;
                if (updated_state == current_target)
                    return 0;
            }

            ctx.candidate_state_responses.clear();

            // Check for long-awaited responses and re-request them.
            for (auto &[hash, request] : ctx.submitted_requests)
            {
                if (should_stop_request_loop(current_target))
                    return 0;

                if (request.waiting_time < REQUEST_RESUBMIT_TIMEOUT)
                {
                    // Increment wait time.
                    request.waiting_time += REQUEST_LOOP_WAIT;
                }
                else
                {
                    if (++resubmissions_count > ABANDON_THRESHOLD)
                    {
                        LOG_INFO << "State sync: Resubmission threshold exceeded. Abandoning sync.";
                        return -1;
                    }

                    // Reset the counter and re-submit request.
                    request.waiting_time = 0;
                    LOG_DEBUG << "State sync: Resubmitting request...";
                    submit_request(request, lcl);
                }
            }

            // Check whether we can submit any more requests.
            if (!ctx.pending_requests.empty() && ctx.submitted_requests.size() < MAX_AWAITING_REQUESTS)
            {
                const uint16_t available_slots = MAX_AWAITING_REQUESTS - ctx.submitted_requests.size();
                for (int i = 0; i < available_slots && !ctx.pending_requests.empty(); i++)
                {
                    if (should_stop_request_loop(current_target))
                        return 0;

                    const backlog_item &request = ctx.pending_requests.front();
                    submit_request(request, lcl);
                    ctx.pending_requests.pop_front();
                }
            }
        }

        return 0;
    }

    /**
     * Vadidated the received hash against the received fs entry map.
     * @param vpath Virtual path of the fs.
     * @param hash Received hash.
     * @param fs_entry_map Received fs entry map.
     * @returns true if hash is valid, otherwise false.
    */
    bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entry_map)
    {
        hpfs::h32 content_hash;

        // Initilal hash is vpath hash.
        content_hash = crypto::get_hash(vpath);

        // Then XOR the file hashes to the initial hash.
        for (const auto &[name, fs_entry] : fs_entry_map)
        {
            content_hash ^= fs_entry.hash;
        }

        return content_hash.to_string_view() == hash;
    }

    /**
     * Vadidated the received hash against the received file hash map.
     * @param vpath Virtual path of the file.
     * @param hash Received hash.
     * @param hashes Received block hashes.
     * @param hash_count Size of the hash list.
     * @returns true if hash is valid, otherwise false.
    */
    bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const hpfs::h32 *hashes, const size_t hash_count)
    {
        hpfs::h32 content_hash = hpfs::h32_empty;

        // Initilal hash is vpath hash.
        content_hash = crypto::get_hash(vpath);

        // Then XOR the block hashes to the initial hash.
        for (int32_t block_id = 0; block_id < hash_count; block_id++)
        {
            content_hash ^= hashes[block_id];
        }

        return content_hash.to_string_view() == hash;
    }

    /**
     * Vadidated the received hash against the received block.
     * @param hash Received hash.
     * @param block_id Id of the block.
     * @param buf Block buffer.
     * @returns true if hash is valid, otherwise false.
    */
    bool validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf)
    {
        // Calculate block offset of this block.
        const off_t block_offset = block_id * hpfs::BLOCK_SIZE;
        std::string_view offset = std::string_view(reinterpret_cast<const char *>(&block_offset), sizeof(off_t));
        return crypto::get_hash(offset, buf) == hash;
    }

    /**
     * Indicates whether to break out of state request processing loop.
     */
    bool should_stop_request_loop(const hpfs::h32 current_target)
    {
        if (ctx.is_shutting_down)
            return true;

        // Stop request loop if the target has changed.
        std::shared_lock lock(ctx.target_state_mutex);
        return current_target != ctx.target_state;
    }

    /**
     * Sends a state request to a random peer.
     * @param path Requested file or dir path.
     * @param is_file Whether the requested path if a file or dir.
     * @param block_id The requested block id. Only relevant if requesting a file block. Otherwise -1.
     * @param expected_hash The expected hash of the requested data. The peer will ignore the request if their hash is different.
     * @param target_pubkey The peer pubkey the request was submitted to.
     */
    void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                 const hpfs::h32 expected_hash, std::string_view lcl, std::string &target_pubkey)
    {
        p2p::state_request sr;
        sr.parent_path = path;
        sr.is_file = is_file;
        sr.block_id = block_id;
        sr.expected_hash = expected_hash;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_state_request(fbuf, sr, lcl);
        p2p::send_message_to_random_peer(fbuf, target_pubkey); //todo: send to a node that hold the majority state to improve reliability of retrieving state.
    }

    /**
     * Submits a pending state request to the peer.
     */
    void submit_request(const backlog_item &request, std::string_view lcl)
    {
        const std::string key = std::string(request.path)
                                    .append(reinterpret_cast<const char *>(&request.expected_hash), sizeof(hpfs::h32));
        ctx.submitted_requests.try_emplace(key, request);

        const bool is_file = request.type != BACKLOG_ITEM_TYPE::DIR;
        std::string target_pubkey;
        request_state_from_peer(request.path, is_file, request.block_id, request.expected_hash, lcl, target_pubkey);

        if (!target_pubkey.empty())
            LOG_DEBUG << "State sync: Requesting from [" << target_pubkey.substr(2, 10) << "]. type:" << request.type
                      << " path:" << request.path << " block_id:" << request.block_id
                      << " hash:" << request.expected_hash;
    }

    /**
     * Process dir children response.
     * @param vpath Virtual path of the fs.
     * @param fs_entry_map Received fs entry map.
     * @returns 0 on success, otherwise -1.
     */
    int handle_fs_entry_response(std::string_view vpath, std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entry_map)
    {
        // Get the parent path of the fs entries we have received.
        LOG_DEBUG << "State sync: Processing fs entries response for " << vpath;

        // Create physical directory on our side if not exist.
        std::string parent_physical_path = std::string(ctx.hpfs_mount_dir).append(vpath);
        if (util::create_dir_tree_recursive(parent_physical_path) == -1)
            return -1;

        // Get the children hash entries and compare with what we got from peer.
        std::vector<hpfs::child_hash_node> existing_fs_entries;
        if (hpfs::get_dir_children_hashes(existing_fs_entries, ctx.hpfs_mount_dir, vpath) == -1)
            return -1;

        // Request more info on fs entries that exist on both sides but are different.
        for (const auto &ex_entry : existing_fs_entries)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(vpath)
                                          .append(vpath.back() != '/' ? "/" : "")
                                          .append(ex_entry.name);

            const auto peer_itr = fs_entry_map.find(ex_entry.name);
            if (peer_itr != fs_entry_map.end())
            {
                // Request state if hash is different.
                if (peer_itr->second.hash != ex_entry.hash)
                {
                    // Prioritize file state requests over directories.
                    if (ex_entry.is_file)
                        ctx.pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, child_vpath, -1, peer_itr->second.hash});
                    else
                        ctx.pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, child_vpath, -1, peer_itr->second.hash});
                }

                fs_entry_map.erase(peer_itr);
            }
            else
            {
                // If there was an entry that does not exist on other side, delete it.
                std::string child_physical_path = std::string(ctx.hpfs_mount_dir).append(child_vpath);

                if ((ex_entry.is_file && unlink(child_physical_path.c_str()) == -1) ||
                    !ex_entry.is_file && util::remove_directory_recursively(child_physical_path.c_str()) == -1)
                    return -1;

                LOG_DEBUG << "State sync: Deleted " << (ex_entry.is_file ? "file" : "dir") << " path " << child_vpath;
            }
        }

        // Queue the remaining peer fs entries (that our side does not have at all) to request.
        for (const auto &[name, fs_entry] : fs_entry_map)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(vpath)
                                          .append(vpath.back() != '/' ? "/" : "")
                                          .append(name);

            // Prioritize file state requests over directories.
            if (fs_entry.is_file)
                ctx.pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, child_vpath, -1, fs_entry.hash});
            else
                ctx.pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, child_vpath, -1, fs_entry.hash});
        }

        return 0;
    }

    /**
     * Process file block hash map response.
     * @param vpath Virtual path of the file.
     * @param hash Received hash.
     * @param hashes Received block hashes.
     * @param file_length Size of the file.
     * @returns 0 on success, otherwise -1.
     */
    int handle_file_hashmap_response(std::string_view vpath, const hpfs::h32 *hashes, const size_t hash_count, const uint64_t file_length)
    {
        // Get the file path of the block hashes we have received.
        LOG_DEBUG << "State sync: Processing file block hashes response for " << vpath;

        // File block hashes on our side (file might not exist on our side).
        std::vector<hpfs::h32> existing_hashes;
        if (hpfs::get_file_block_hashes(existing_hashes, ctx.hpfs_mount_dir, vpath) == -1 && errno != ENOENT)
            return -1;
        const size_t existing_hash_count = existing_hashes.size();

        // Compare the block hashes and request any differences.
        auto insert_itr = ctx.pending_requests.begin();
        const int32_t max_block_id = MAX(existing_hash_count, hash_count) - 1;
        for (int32_t block_id = 0; block_id <= max_block_id; block_id++)
        {
            // Insert at front to give priority to block requests while preserving block order.
            if (block_id >= existing_hash_count || existing_hashes[block_id] != hashes[block_id])
                ctx.pending_requests.insert(insert_itr, backlog_item{BACKLOG_ITEM_TYPE::BLOCK, std::string(vpath), block_id, hashes[block_id]});
        }

        if (existing_hashes.size() >= hash_count)
        {
            // If peer file might be smaller, truncate our file to match with peer file.
            std::string file_physical_path = std::string(ctx.hpfs_mount_dir).append(vpath);
            if (truncate(file_physical_path.c_str(), file_length) == -1)
                return -1;
        }

        return 0;
    }

    /**
     * Process file block response.
     * @param vpath Virtual path of the file.
     * @param block_id Id of the block.
     * @param buf Block buffer.
     * @returns 0 on success, otherwise -1.
     */
    int handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf)
    {
        LOG_DEBUG << "State sync: Writing block_id " << block_id
                  << " (len:" << buf.length()
                  << ") of " << vpath;

        std::string file_physical_path = std::string(ctx.hpfs_mount_dir).append(vpath);
        const int fd = open(file_physical_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << " Open failed " << file_physical_path;
            return -1;
        }

        const off_t offset = block_id * state_common::BLOCK_SIZE;
        const int res = pwrite(fd, buf.data(), buf.length(), offset);
        close(fd);
        if (res < buf.length())
        {
            LOG_ERROR << errno << " Write failed " << file_physical_path;
            return -1;
        }

        return 0;
    }

} // namespace state_sync