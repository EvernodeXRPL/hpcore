#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../ledger/ledger.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"
#include "hpfs_sync.hpp"
#include "../sc/sc.hpp"
#include "../unl.hpp"

namespace hpfs
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

    /**
     * This should be called to activate the hpfs sync.
     */
    int hpfs_sync::init(std::string_view worker_name, hpfs::hpfs_mount *fs_mount_ptr)
    {
        if (fs_mount_ptr == NULL)
            return -1;

        name = worker_name;
        fs_mount = fs_mount_ptr;
        hpfs_sync_thread = std::thread(&hpfs_sync::hpfs_syncer_loop, this);
        init_success = true;
        return 0;
    }

    /**
     * Perform relavent cleaning.
     */
    void hpfs_sync::deinit()
    {
        if (init_success)
        {
            is_syncing = false;
            is_shutting_down = true;
            hpfs_sync_thread.join();
        }
    }

    /**
     * Sets a list of sync targets. Sync finishes when all the targets are synced.
     * Syncing happens sequentially.
     * @param sync_target_list List of sync targets to sync towards.
     */
    void hpfs_sync::set_target(const std::list<sync_target> &sync_target_list)
    {
        if (sync_target_list.empty())
            return;

        // Do not do anything if we are already syncing towards the specified target states.
        if (is_shutting_down || (is_syncing && original_target_list == sync_target_list))
            return;

        original_target_list = sync_target_list;
        target_list = std::move(sync_target_list);

        std::unique_lock lock(current_target_mutex);
        current_target = target_list.front(); // Make the first element of the list the first target to sync.
        is_syncing = true;
    }

    /**
     * This sets a prioritized sync target. This target will replace current sync target.
     * This target will immediately starting to sync and the interupted sync will resume
     * once this sync target is acheived.
    */
    void hpfs_sync::set_target_push_front(const sync_target &target)
    {
        {
            std::shared_lock lock(current_target_mutex);
            if (is_shutting_down || (is_syncing && current_target == target))
                return;
        }

        target_list.push_front(target);
        is_syncing = true;
        std::unique_lock lock(current_target_mutex);
        // Make the first element of the list the first target to sync.
        current_target = target_list.front();
    }

    /**
     * Adds a new target to the syncing list. If the list was previously empty, current target
     * will be updated and syncing will start.
    */
    void hpfs_sync::set_target_push_back(const sync_target &target)
    {
        // Current_target_mutex is not required since this function is currently used in a unique_lock
        // scope.
        if (is_shutting_down || (is_syncing && current_target == target))
            return;

        // Check whether this target is already in the sync target list.
        const auto itr = std::find(target_list.begin(), target_list.end(), target);
        if (itr != target_list.end())
            return;

        target_list.push_back(target);
        if (!is_syncing)
        {
            std::unique_lock lock(current_target_mutex);
            // Make the first element of the list the first target to sync.
            current_target = target_list.front();
            is_syncing = true;
        }
    }

    /**
     * Runs the hpfs sync worker loop.
     */
    void hpfs_sync::hpfs_syncer_loop()
    {
        util::mask_signal();

        LOG_INFO << "Hpfs " << name << " sync: Worker started.";

        while (!is_shutting_down)
        {
            util::sleep(IDLE_WAIT);

            // Keep idling if we are not doing any sync activity.

            if (!is_syncing)
                continue;

            bool is_sync_complete = false;
            if (fs_mount->acquire_rw_session() != -1)
            {
                while (!is_shutting_down)
                {
                    {
                        std::shared_lock lock(current_target_mutex);
                        LOG_INFO << "Hpfs " << name << " sync: Starting sync for target " << current_target.name << " hash: " << current_target.hash;
                    }
                    util::h32 new_state = util::h32_empty;
                    const int result = request_loop(current_target.hash, new_state);

                    pending_requests.clear();
                    candidate_hpfs_responses.clear();
                    submitted_requests.clear();

                    if (result == -1 || result == 1 || is_shutting_down)
                        break;

                    {
                        std::unique_lock lock(current_target_mutex);

                        if (new_state == current_target.hash)
                        {
                            LOG_INFO << "Hpfs " << name << " sync: Target " << current_target.name << " hash achieved: " << new_state;
                            on_current_sync_state_acheived(current_target);

                            // Start syncing to next target.
                            const int result = start_syncing_next_target();
                            if (result == 0)
                                break;
                            else if (result == 1)
                                continue;
                        }
                        else
                        {
                            LOG_INFO << "Hpfs " << name << " sync: Continuing sync for new " << current_target.name << " hash: " << current_target.hash;
                            continue;
                        }
                    }
                }
                fs_mount->release_rw_session();
                is_sync_complete = true;
            }
            else
            {
                LOG_ERROR << "Hpfs " << name << " sync: Failed to start hpfs rw session";
            }
            // Clear target list and original target list since the sync is complete.
            target_list = {};
            original_target_list = {};
            is_syncing = false;
            const sync_target last_sync_target = current_target;
            current_target = {};
            if (is_sync_complete)
                on_sync_complete(last_sync_target);
        }

        LOG_INFO << "Hpfs " << name << " sync: Worker stopped.";
    }

    /**
     * Reqest loop.
     * @return -1 on error. 0 when current sync state acheived or sync is stopped due to target change.
     * Returns 1 on successfully finishing all the sync targets.
    */
    int hpfs_sync::request_loop(const util::h32 current_target_hash, util::h32 &updated_state)
    {
        p2p::sequence_hash last_primary_shard_id = ledger::ctx.get_last_primary_shard_id();

        // Send the initial root hpfs request of the current target.
        submit_request(backlog_item{current_target.item_type, current_target.vpath, -1, current_target_hash}, last_primary_shard_id);

        // Indicates whether any responses were processed in the previous loop iteration.
        bool prev_responses_processed = false;

        // No. of repetitive resubmissions so far. (This is reset whenever we receive a hpfs response)
        uint16_t resubmissions_count = 0;

        while (!should_stop_request_loop(current_target_hash))
        {
            // Wait a small delay if there were no responses processed during previous iteration.
            if (!prev_responses_processed)
                util::sleep(REQUEST_LOOP_WAIT);

            // Get the current last shard information.
            last_primary_shard_id = ledger::ctx.get_last_primary_shard_id();

            // Move the received hpfs responses to the local response list.
            swap_collected_responses();

            prev_responses_processed = !candidate_hpfs_responses.empty();

            // Reset resubmissions counter whenever we have a resposne.
            if (!candidate_hpfs_responses.empty())
                resubmissions_count = 0;

            for (auto &response : candidate_hpfs_responses)
            {
                if (should_stop_request_loop(current_target_hash))
                    return 0;

                LOG_DEBUG << "Hpfs " << name << " sync: Processing hpfs response from [" << response.first.substr(2, 10) << "]";

                const msg::fbuf::p2pmsg::Content *content = msg::fbuf::p2pmsg::GetContent(response.second.data());
                const msg::fbuf::p2pmsg::Hpfs_Response_Message *resp_msg = content->message_as_Hpfs_Response_Message();

                // Check whether we are actually waiting for this response. If not, ignore it.
                std::string_view hash = msg::fbuf::flatbuff_bytes_to_sv(resp_msg->hash());
                std::string_view vpath = msg::fbuf::flatbuff_str_to_sv(resp_msg->path());

                const std::string key = std::string(vpath).append(hash);
                const auto pending_resp_itr = submitted_requests.find(key);
                if (pending_resp_itr == submitted_requests.end())
                {
                    LOG_DEBUG << "Hpfs " << name << " sync: Skipping hpfs response due to hash mismatch.";
                    continue;
                }

                // Process the message based on response type.
                const msg::fbuf::p2pmsg::Hpfs_Response msg_type = resp_msg->hpfs_response_type();

                if (msg_type == msg::fbuf::p2pmsg::Hpfs_Response_Fs_Entry_Response)
                {
                    const msg::fbuf::p2pmsg::Fs_Entry_Response *fs_resp = resp_msg->hpfs_response_as_Fs_Entry_Response();

                    // Get fs entries we have received.
                    std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> peer_fs_entry_map;
                    msg::fbuf::p2pmsg::flatbuf_hpfsfshashentry_to_hpfsfshashentry(peer_fs_entry_map, fs_resp->entries());

                    // Commented for now. Need to change the way the hash is calculated once the flatbuffer re-architecture finishes.
                    // Validate received fs data against the hash.
                    // if (!validate_fs_entry_hash(vpath, hash, peer_fs_entry_map))
                    // {
                    //     LOG_INFO << "Hpfs " << name << " sync: Skipping hpfs response due to fs entry hash mismatch.";
                    //     continue;
                    // }

                    handle_fs_entry_response(vpath, peer_fs_entry_map);
                }
                else if (msg_type == msg::fbuf::p2pmsg::Hpfs_Response_File_HashMap_Response)
                {
                    const msg::fbuf::p2pmsg::File_HashMap_Response *file_resp = resp_msg->hpfs_response_as_File_HashMap_Response();

                    // File block hashes we received from the peer.
                    const util::h32 *peer_hashes = reinterpret_cast<const util::h32 *>(file_resp->hash_map()->data());
                    const size_t peer_hash_count = file_resp->hash_map()->size() / sizeof(util::h32);

                    // Commented for now. Need to change the way the hash is calculated once the flatbuffer re-architecture finishes.
                    // Validate received hashmap against the hash.
                    // if (!validate_file_hashmap_hash(vpath, hash, peer_hashes, peer_hash_count))
                    // {
                    //     LOG_INFO << "Hpfs " << name << " sync: Skipping hpfs response due to file hashmap hash mismatch.";
                    //     continue;
                    // }

                    handle_file_hashmap_response(vpath, peer_hashes, peer_hash_count, file_resp->file_length());
                }
                else if (msg_type == msg::fbuf::p2pmsg::Hpfs_Response_Block_Response)
                {
                    const msg::fbuf::p2pmsg::Block_Response *block_resp = resp_msg->hpfs_response_as_Block_Response();

                    // Get the file path of the block data we have received.
                    const uint32_t block_id = block_resp->block_id();
                    std::string_view buf = msg::fbuf::flatbuff_bytes_to_sv(block_resp->data());

                    // Commented for now. Need to change the way the hash is calculated once the flatbuffer re-architecture finishes.
                    // Validate received block data against the hash.
                    // if (!validate_file_block_hash(hash, block_id, buf))
                    // {
                    //     LOG_INFO << "Hpfs " << name << " sync: Skipping hpfs response due to file block hash mismatch.";
                    //     continue;
                    // }

                    handle_file_block_response(vpath, block_id, buf);
                }

                // Now that we have received matching hash and handled it, remove it from the waiting list.
                submitted_requests.erase(pending_resp_itr);

                // After handling each response, check whether we have reached target hpfs state.
                // get_hash returns 0 incase target parent is not existing in our side.
                if (fs_mount->get_hash(updated_state, hpfs::RW_SESSION_NAME, current_target.vpath) == -1)
                {
                    LOG_ERROR << "Hpfs " << name << " sync: exiting due to hash check error.";
                    return -1;
                }

                // Update the central hpfs state tracker.
                fs_mount->set_parent_hash(current_target.vpath, updated_state);

                LOG_DEBUG << "Hpfs " << name << " sync: current:" << updated_state << " | target:" << current_target_hash;
                if (updated_state == current_target_hash)
                    return 0;
            }

            candidate_hpfs_responses.clear();

            // No. of milliseconds to wait before resubmitting a request.
            const uint32_t request_resubmit_timeout = hpfs::get_request_resubmit_timeout();

            // Check for long-awaited responses and re-request them.
            for (auto &[hash, request] : submitted_requests)
            {
                if (should_stop_request_loop(current_target_hash))
                    return 0;

                if (request.waiting_time < request_resubmit_timeout)
                {
                    // Increment wait time.
                    request.waiting_time += REQUEST_LOOP_WAIT;
                }
                else
                {
                    if (++resubmissions_count > ABANDON_THRESHOLD)
                    {
                        LOG_INFO << "Hpfs " << name << " sync: Resubmission threshold exceeded. Abandoning sync.";

                        std::unique_lock lock(current_target_mutex);
                        const int result = start_syncing_next_target();
                        if (result == 0)
                        {
                            current_target = {};
                            on_sync_abandoned();
                            return 1; // To stop syncing since we have sync all the targets.
                        }
                        return 0;
                    }

                    // Reset the counter and re-submit request.
                    request.waiting_time = 0;
                    LOG_DEBUG << "Hpfs " << name << " sync: Resubmitting request...";
                    submit_request(request, last_primary_shard_id);
                }
            }

            // Check whether we can submit any more requests.
            if (!pending_requests.empty() && submitted_requests.size() < MAX_AWAITING_REQUESTS)
            {
                const uint16_t available_slots = MAX_AWAITING_REQUESTS - submitted_requests.size();
                for (int i = 0; i < available_slots && !pending_requests.empty(); i++)
                {
                    if (should_stop_request_loop(current_target_hash))
                        return 0;

                    const backlog_item &request = pending_requests.front();
                    submit_request(request, last_primary_shard_id);
                    pending_requests.pop_front();
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
    bool hpfs_sync::validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map)
    {
        util::h32 content_hash;

        const std::string vpath_name = util::get_name(vpath);

        // Initilal hash is vpath hash.
        content_hash = crypto::get_hash(vpath_name);

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
    bool hpfs_sync::validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const util::h32 *hashes, const size_t hash_count)
    {
        util::h32 content_hash = util::h32_empty;

        const std::string vpath_name = util::get_name(vpath);

        // Initilal hash is vpath hash.
        content_hash = crypto::get_hash(vpath_name);

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
    bool hpfs_sync::validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf)
    {
        // Calculate block offset of this block.
        const off_t block_offset = block_id * hpfs::BLOCK_SIZE;
        std::string_view offset = std::string_view(reinterpret_cast<const char *>(&block_offset), sizeof(off_t));
        return crypto::get_hash(offset, buf) == hash;
    }

    /**
     * Indicates whether to break out of hpfs request processing loop.
     */
    bool hpfs_sync::should_stop_request_loop(const util::h32 &current_target_hash)
    {
        if (is_shutting_down)
            return true;

        // Stop request loop if the target has changed.
        std::shared_lock lock(current_target_mutex);
        return current_target_hash != current_target.hash;
    }

    /**
     * Sends a hpfs request to a random peer.
     * @param path Requested file or dir path.
     * @param is_file Whether the requested path if a file or dir.
     * @param block_id The requested block id. Only relevant if requesting a file block. Otherwise -1.
     * @param expected_hash The expected hash of the requested data. The peer will ignore the request if their hash is different.
     * @param last_primary_shard_id The last primary shard id.
     * @param target_pubkey The peer pubkey the request was submitted to.
     */
    void hpfs_sync::request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                            const util::h32 expected_hash, const p2p::sequence_hash &last_primary_shard_id, std::string &target_pubkey)
    {
        p2p::hpfs_request hr;
        hr.parent_path = path;
        hr.is_file = is_file;
        hr.block_id = block_id;
        hr.expected_hash = expected_hash;
        hr.mount_id = fs_mount->mount_id;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        msg::fbuf::p2pmsg::create_msg_from_hpfs_request(fbuf, hr, last_primary_shard_id);
        p2p::send_message_to_random_peer(fbuf, target_pubkey); //todo: send to a node that hold the majority hpfs state to improve reliability of retrieving hpfs state.
    }

    /**
     * Submits a pending hpfs request to the peer.
     */
    void hpfs_sync::submit_request(const backlog_item &request, const p2p::sequence_hash &last_primary_shard_id)
    {
        const std::string key = std::string(request.path)
                                    .append(reinterpret_cast<const char *>(&request.expected_hash), sizeof(util::h32));
        submitted_requests.try_emplace(key, request);

        const bool is_file = request.type != BACKLOG_ITEM_TYPE::DIR;
        std::string target_pubkey;
        request_state_from_peer(request.path, is_file, request.block_id, request.expected_hash, last_primary_shard_id, target_pubkey);

        if (!target_pubkey.empty())
            LOG_DEBUG << "Hpfs " << name << " sync: Requesting from [" << target_pubkey.substr(2, 10) << "]. type:" << request.type
                      << " path:" << request.path << " block_id:" << request.block_id
                      << " hash:" << request.expected_hash;
    }

    /**
     * Process dir children response.
     * @param vpath Virtual path of the fs.
     * @param fs_entry_map Received fs entry map.
     * @returns 0 on success, otherwise -1.
     */
    int hpfs_sync::handle_fs_entry_response(std::string_view vpath, std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map)
    {
        // Get the parent path of the fs entries we have received.
        LOG_DEBUG << "Hpfs " << name << " sync: Processing fs entries response for " << vpath;

        // Create physical directory on our side if not exist.
        std::string parent_physical_path = fs_mount->rw_dir + vpath.data();
        if (util::create_dir_tree_recursive(parent_physical_path) == -1)
            return -1;

        // Get the children hash entries and compare with what we got from peer.
        std::vector<hpfs::child_hash_node> existing_fs_entries;
        if (fs_mount->get_dir_children_hashes(existing_fs_entries, hpfs::RW_SESSION_NAME, vpath) == -1)
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
                // Request hpfs state if hash is different.
                if (peer_itr->second.hash != ex_entry.hash)
                {
                    // Prioritize file hpfs requests over directories.
                    if (ex_entry.is_file)
                        pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, child_vpath, -1, peer_itr->second.hash});
                    else
                        pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, child_vpath, -1, peer_itr->second.hash});
                }

                fs_entry_map.erase(peer_itr);
            }
            else
            {
                // If there was an entry that does not exist on other side, delete it.
                std::string child_physical_path = fs_mount->rw_dir + child_vpath.data();

                if ((ex_entry.is_file && unlink(child_physical_path.c_str()) == -1) ||
                    !ex_entry.is_file && util::remove_directory_recursively(child_physical_path.c_str()) == -1)
                    return -1;

                LOG_DEBUG << "Hpfs " << name << " sync: Deleted " << (ex_entry.is_file ? "file" : "dir") << " path " << child_vpath;
            }
        }

        // Queue the remaining peer fs entries (that our side does not have at all) to request.
        for (const auto &[name, fs_entry] : fs_entry_map)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(vpath)
                                          .append(vpath.back() != '/' ? "/" : "")
                                          .append(name);

            // Prioritize file hpfs requests over directories.
            if (fs_entry.is_file)
                pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, child_vpath, -1, fs_entry.hash});
            else
                pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, child_vpath, -1, fs_entry.hash});
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
    int hpfs_sync::handle_file_hashmap_response(std::string_view vpath, const util::h32 *hashes, const size_t hash_count, const uint64_t file_length)
    {
        // Get the file path of the block hashes we have received.
        LOG_DEBUG << "Hpfs " << name << " sync: Processing file block hashes response for " << vpath;

        // File block hashes on our side (file might not exist on our side).
        std::vector<util::h32> existing_hashes;
        if (fs_mount->get_file_block_hashes(existing_hashes, hpfs::RW_SESSION_NAME, vpath) == -1 && errno != ENOENT)
            return -1;
        const size_t existing_hash_count = existing_hashes.size();

        // Compare the block hashes and request any differences.
        auto insert_itr = pending_requests.begin();
        const int32_t max_block_id = MAX(existing_hash_count, hash_count) - 1;
        for (int32_t block_id = 0; block_id <= max_block_id; block_id++)
        {
            // Insert at front to give priority to block requests while preserving block order.
            if (block_id >= existing_hash_count || existing_hashes[block_id] != hashes[block_id])
                pending_requests.insert(insert_itr, backlog_item{BACKLOG_ITEM_TYPE::BLOCK, std::string(vpath), block_id, hashes[block_id]});
        }

        if (existing_hashes.size() >= hash_count)
        {
            // If peer file might be smaller, truncate our file to match with peer file.
            std::string file_physical_path = fs_mount->rw_dir + vpath.data();
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
    int hpfs_sync::handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf)
    {
        LOG_DEBUG << "Hpfs " << name << " sync: Writing block_id " << block_id
                  << " (len:" << buf.length()
                  << ") of " << vpath;

        std::string file_physical_path = fs_mount->rw_dir + vpath.data();
        const int fd = open(file_physical_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << " Open failed " << file_physical_path;
            return -1;
        }

        const off_t offset = block_id * hpfs::BLOCK_SIZE;
        const int res = pwrite(fd, buf.data(), buf.length(), offset);
        close(fd);
        if (res < buf.length())
        {
            LOG_ERROR << errno << " Write failed " << file_physical_path;
            return -1;
        }

        return 0;
    }

    /**
     * This method can be used to invoke mount specific custom logic (after overriding this method) to be executed after
     * a sync target is acheived.
    */
    void hpfs_sync::on_current_sync_state_acheived(const sync_target &synced_target)
    {
    }

    /**
     * This method can be used to invoke mount specific custom logic (after overriding this method) to be executed after
     * a sync is abondened.
    */
    void hpfs_sync::on_sync_abandoned()
    {
    }

    /**
     * This method can be used to invoke mount specific custom logic (after overriding this method) to be executed after
     * a full sync is complete.
    */
    void hpfs_sync::on_sync_complete(const sync_target &last_sync_target)
    {
        LOG_INFO << "Hpfs " << name << " sync: All parents synced.";
    }

    /**
     * Starts syncing next target if available after current target finishes.
     * @return returns 0 when the full sync is complete and 1 when more sync targets are available.
    */
    int hpfs_sync::start_syncing_next_target()
    {
        target_list.pop_front(); // Remove the synced parent from the target list.
        if (target_list.empty())
        {
            return 0;
        }
        else
        {
            current_target = target_list.front();
            return 1;
        }
    }

} // namespace hpfs