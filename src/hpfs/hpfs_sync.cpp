#include "../pchheader.hpp"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../msg/fbuf/p2pmsg_generated.h"
#include "../msg/fbuf/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"
#include "../crypto.hpp"
#include "hpfs_sync.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace hpfs
{
    // Idle loop sleep time  (milliseconds).
    constexpr uint16_t IDLE_WAIT = 40;

    // Max number of requests that can be awaiting response at any given time.
    constexpr uint16_t MAX_AWAITING_REQUESTS = 4;

    // Max no. of repetitive reqeust resubmissions before abandoning the sync.
    constexpr uint16_t ABANDON_THRESHOLD = 20;

    // No. of mulliseconds to wait before reacquiring hpfs rw session.
    constexpr uint16_t HPFS_REAQUIRE_WAIT = 10;

    constexpr int FILE_PERMS = 0644;

// Locates the ongoing target for the provided request vpath. (Matched if target vpath is an ancestor path of the request vpath)
#define TARGET_OF_REQUEST(req_vpath) std::find_if(ongoing_targets.begin(), ongoing_targets.end(), [&](sync_item &t) { return req_vpath.rfind(t.vpath, 0) == 0; })

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
     * Add or update a sync target.
     * @param is_dir whether the sync target is a dir or file.
     * @param vpath The vpath of to sync.
     * @param hash Target hash to achieve.
     * @param high_priority Whether this target should be given higher priority over other ongoing targets.
     */
    void hpfs_sync::set_target(const bool is_dir, const std::string &vpath,
                               const util::h32 &hash, const bool high_priority)
    {
        std::unique_lock lock(incoming_targets_mutex);
        incoming_targets.emplace(sync_item{
            (is_dir ? SYNC_ITEM_TYPE::DIR : SYNC_ITEM_TYPE::FILE), vpath, -1, hash, high_priority});
        is_syncing = true;
    }

    /**
     * Runs the hpfs sync worker loop.
     */
    void hpfs_sync::hpfs_syncer_loop()
    {
        util::mask_signal();
        LOG_INFO << "Hpfs " << name << " sync: Worker started.";

        // Indicates whether any responses were processed in the previous loop iteration.
        bool prev_responses_processed = false;

        while (!is_shutting_down)
        {
            // Wait a small delay if there were no responses processed during previous iteration.
            if (!prev_responses_processed)
                util::sleep(IDLE_WAIT);

            prev_responses_processed = false;

            // Check whether we have any new/changed targets.
            if (check_incoming_targets() == -1)
            {
                LOG_INFO << "Hpfs " << name << " sync: Sopping worker due to error in target check.";
                break;
            }

            // Move the received hpfs responses to the local response list.
            swap_collected_responses();

            if (ongoing_targets.empty())
            {
                candidate_hpfs_responses.clear();
                continue;
            }

            // Process any sync responses we have received.
            prev_responses_processed = process_candidate_responses();

            if (is_shutting_down)
                break;

            // Submit any pending requests to peers.
            perform_request_submissions();
        }

        if (rw_session_active)
            fs_mount->release_rw_session();

        LOG_INFO << "Hpfs " << name << " sync: Worker stopped.";
    }

    /**
     * Checks for any new/updated targets that we have received and safely incorporates them into ongoing sync activity.
     * @return o on success. -1 on error.
     */
    int hpfs_sync::check_incoming_targets()
    {
        {
            std::unique_lock lock(incoming_targets_mutex);
            for (const sync_item &target : incoming_targets)
            {
                // If we have an ongoing target with the same vpath but having a different hash, we need to destroy
                // that target and insert the updated one.

                const auto ex_target = std::find_if(ongoing_targets.begin(), ongoing_targets.end(),
                                                    [&](sync_item &t)
                                                    { return t.vpath == target.vpath; });
                if (ex_target == ongoing_targets.end())
                {
                    ongoing_targets.push_back(target);
                    pending_requests.emplace(target); // Places the root request for this target according to priority sorting.

                    LOG_INFO << "Hpfs " << name << " sync: Target added. Hash:" << target.expected_hash << " " << target.vpath;
                }
                else if (ex_target->expected_hash != target.expected_hash)
                {
                    // Existing target's expected hash is obsolete now. Therefore clear all ongoing activity for the obsolete target.
                    clear_target(ex_target);

                    ongoing_targets.push_back(target); // Insert the new one to replace the obsolete target.
                    pending_requests.emplace(target);  // Places the root request for this target according to 'sync_item' priority sorting.

                    LOG_INFO << "Hpfs " << name << " sync: Target updated. New hash:" << target.expected_hash << " " << target.vpath;
                }
            }

            incoming_targets.clear();
        }

        // Acquire/release hpfs rw session as needed.
        if (!rw_session_active && !ongoing_targets.empty())
        {
            if (fs_mount->acquire_rw_session() == -1)
            {
                LOG_ERROR << "Hpfs " << name << " sync: Failed to start hpfs rw session";
                return -1;
            }
            rw_session_active = true;
        }
        else if (rw_session_active && ongoing_targets.empty())
        {
            if (fs_mount->release_rw_session() == -1)
            {
                LOG_ERROR << "Hpfs " << name << " sync: Failed to release hpfs rw session";
                return -1;
            }
            rw_session_active = false;
        }

        return 0;
    }

    /**
     * Clears the specified ongoing target and its associated requests.
     * @param target_itr Iterator in the ongoing targets to be erased.
     */
    void hpfs_sync::clear_target(const std::vector<hpfs::sync_item>::iterator &target_itr)
    {
        // Clear pending requests under the obsolete target.
        {
            auto itr = pending_requests.begin();
            while (itr != pending_requests.end())
            {
                if (itr->vpath.rfind(target_itr->vpath, 0) == 0) // If the request is a sub path of the target's vpath.
                    pending_requests.erase(itr++);
                else
                    ++itr;
            }
        }

        // Clear submitted requests under the obsolete target.
        {
            auto itr = submitted_requests.begin();
            while (itr != submitted_requests.end())
            {
                if (itr->second.vpath.rfind(target_itr->vpath, 0) == 0) // If the request is a sub path of the target's vpath.
                    submitted_requests.erase(itr++);
                else
                    ++itr;
            }
        }

        ongoing_targets.erase(target_itr); // Clear the obsolete target.
    }

    /**
     * Submits requests from pending collection to peers, based on request throughput availabilty.
     */
    void hpfs_sync::perform_request_submissions()
    {
        // No. of milliseconds to wait before resubmitting a request.
        const uint32_t request_resubmit_timeout = hpfs::get_request_resubmit_timeout();

        // Check for long-awaited responses and re-request them.
        for (auto &[hash, request] : submitted_requests)
        {
            if (is_shutting_down)
                return;

            if (request.waiting_time < request_resubmit_timeout)
            {
                // Increment wait time.
                request.waiting_time += IDLE_WAIT;
            }
            else
            {
                // If we have exceeded continous resubmission threshold, clear everything (all targets) and go back to idle state.
                if (++resubmissions_count > ABANDON_THRESHOLD)
                {
                    pending_requests.clear();
                    submitted_requests.clear();
                    ongoing_targets.clear();
                    update_sync_status();
                    LOG_INFO << "Hpfs " << name << " sync: All targets abandoned due to resubmission threshold.";

                    on_sync_abandoned();
                }
                else
                {
                    // Reset the counter and re-submit request.
                    request.waiting_time = 0;
                    submit_request(request, false, true);
                }
            }
        }

        // Check whether we can submit any more requests from the pending collection.
        if (!pending_requests.empty() && submitted_requests.size() < MAX_AWAITING_REQUESTS)
        {
            const uint16_t available_slots = MAX_AWAITING_REQUESTS - submitted_requests.size();
            for (int i = 0; i < available_slots && !pending_requests.empty(); i++)
            {
                if (is_shutting_down)
                    return;

                submit_request(*pending_requests.begin());
                pending_requests.erase(pending_requests.begin());
            }
        }
    }

    /**
     * Safely updates the global sync status flag based on ongoing and incoming targets.
     */
    void hpfs_sync::update_sync_status()
    {
        std::unique_lock lock(incoming_targets_mutex);
        is_syncing = (!incoming_targets.empty() || !ongoing_targets.empty());
    }

    /**
     * Processes any sync responses we have received and updates the local file system state.
     * @return Whether any responses were processed or not.
     */
    bool hpfs_sync::process_candidate_responses()
    {
        // Reset resubmissions counter whenever we have a resposne.
        if (!candidate_hpfs_responses.empty())
            resubmissions_count = 0;

        const bool responses_processed = !candidate_hpfs_responses.empty();

        for (auto &response : candidate_hpfs_responses)
        {
            if (is_shutting_down)
                return false;

            const std::string from = response.first.substr(2, 8); // Sender pubkey.
            const p2pmsg::P2PMsg &msg = *p2pmsg::GetP2PMsg(response.second.data());
            const p2pmsg::HpfsResponseMsg &resp_msg = *msg.content_as_HpfsResponseMsg();

            // Check whether we are actually waiting for this response. If not, ignore it.
            std::string_view hash = msg::fbuf::flatbuf_bytes_to_sv(resp_msg.hash());
            std::string_view vpath = msg::fbuf::flatbuf_str_to_sv(resp_msg.path());

            const std::string key = std::string(vpath).append(hash);
            const auto pending_resp_itr = submitted_requests.find(key);
            if (pending_resp_itr == submitted_requests.end())
            {
                LOG_DEBUG << "Hpfs " << name << " sync: Skipping response from [" << from << "] because we are not looking for hash:"
                          << util::to_hex(hash).substr(0, 10) << " of " << vpath;
                continue;
            }

            // Process the message based on response type.
            const p2pmsg::HpfsResponse msg_type = resp_msg.content_type();

            if (msg_type == p2pmsg::HpfsResponse_HpfsFsEntryResponse)
            {
                const p2pmsg::HpfsFsEntryResponse &fs_resp = *resp_msg.content_as_HpfsFsEntryResponse();

                // Get fs entries we have received.
                std::vector<p2p::hpfs_fs_hash_entry> peer_fs_entries;
                p2pmsg::flatbuf_hpfsfshashentries_to_hpfsfshashentries(peer_fs_entries, fs_resp.entries());

                // Validate received fs data against the hash.
                if (!validate_fs_entry_hash(vpath, hash, fs_resp.dir_mode(), peer_fs_entries))
                {
                    LOG_INFO << "Hpfs " << name << " sync: Skipping mismatched fs entries response from [" << from << "] for " << vpath;
                    continue;
                }

                LOG_DEBUG << "Hpfs " << name << " sync: Processing fs entries response from [" << from << "] for " << vpath;
                handle_fs_entry_response(vpath, fs_resp.dir_mode(), peer_fs_entries);
            }
            else if (msg_type == p2pmsg::HpfsResponse_HpfsFileHashMapResponse)
            {
                const p2pmsg::HpfsFileHashMapResponse &file_resp = *resp_msg.content_as_HpfsFileHashMapResponse();

                // File block hashes we received from the peer.
                const util::h32 *block_hashes = reinterpret_cast<const util::h32 *>(file_resp.hash_map()->data());
                const size_t block_hash_count = file_resp.hash_map()->size() / sizeof(util::h32);

                // Validate received hashmap against the hash.
                if (!validate_file_hashmap_hash(vpath, hash, file_resp.file_mode(), block_hashes, block_hash_count))
                {
                    LOG_INFO << "Hpfs " << name << " sync: Skipping mismatched hashmap response from [" << from << "] for " << vpath;
                    continue;
                }

                std::set<uint32_t> responded_block_ids;
                {
                    file_resp.responded_block_ids();
                    const uint32_t *ptr = file_resp.responded_block_ids()->data();
                    const size_t count = file_resp.responded_block_ids()->size();
                    for (size_t i = 0; i < count; i++)
                        responded_block_ids.emplace(ptr[i]);
                }

                LOG_DEBUG << "Hpfs " << name << " sync: Processing file block hashes response from [" << from << "] for " << vpath;
                handle_file_hashmap_response(vpath, file_resp.file_mode(), block_hashes, block_hash_count,
                                             responded_block_ids, file_resp.file_length());
            }
            else if (msg_type == p2pmsg::HpfsResponse_HpfsBlockResponse)
            {
                const p2pmsg::HpfsBlockResponse &block_resp = *resp_msg.content_as_HpfsBlockResponse();

                // Get the file path of the block data we have received.
                const uint32_t block_id = block_resp.block_id();
                std::string_view buf = msg::fbuf::flatbuf_bytes_to_sv(block_resp.data());

                // Validate received block data against the hash.
                if (!validate_file_block_hash(hash, block_id, buf))
                {
                    LOG_INFO << "Hpfs " << name << " sync: Skipping mismatched block response from [" << from << "] for block_id:" << block_id
                             << " (len:" << buf.length() << ") of " << vpath;
                    continue;
                }

                LOG_DEBUG << "Hpfs " << name << " sync: Processing block response from [" << from << "] for block_id:" << block_id
                          << " (len:" << buf.length() << ") of " << vpath;
                handle_file_block_response(vpath, block_id, buf);
            }

            // Now that we have received matching hash and handled it successfully, remove it from the waiting list.
            submitted_requests.erase(pending_resp_itr);

            // After handling each response, check whether we have achieved the target hash.
            {
                // Find the ongoing target that this response belongs to.
                const auto target_itr = TARGET_OF_REQUEST(vpath);

                if (target_itr != ongoing_targets.end())
                {
                    const std::string target_vpath = target_itr->vpath;
                    const util::h32 target_hash = target_itr->expected_hash;

                    // get_hash returns 0 incase target parent is not existing in our side.
                    util::h32 updated_hash = util::h32_empty;
                    if (fs_mount->get_hash(updated_hash, hpfs::RW_SESSION_NAME, target_vpath) == -1)
                    {
                        LOG_ERROR << "Hpfs " << name << " sync: Hash check error. " << target_vpath;
                    }

                    // Update the central hpfs state tracker.
                    fs_mount->set_parent_hash(target_vpath, updated_hash);

                    // This target's sync is complete.
                    if (updated_hash == target_hash)
                    {
                        clear_target(target_itr); // Clear the completed target.
                        update_sync_status();
                        LOG_INFO << "Hpfs " << name << " sync: Achieved target:" << target_hash << " " << target_vpath;

                        // When target achieved, release and reacquire the hpfs rw session. This helps any upcoming
                        // ro sessions to get updated file system state.
                        fs_mount->release_rw_session();
                        util::sleep(HPFS_REAQUIRE_WAIT);
                        fs_mount->acquire_rw_session();

                        on_sync_target_acheived(target_vpath, target_hash);
                    }
                    else
                    {
                        LOG_DEBUG << "Hpfs " << name << " sync: Current:" << updated_hash << " | target:" << target_hash << " " << target_vpath;
                    }
                }
                else
                {
                    // We should never hit this error.
                    LOG_ERROR << "Hpfs " << name << " sync: Process response: Failed to locate target matching " << vpath;
                }
            }
        }

        candidate_hpfs_responses.clear();

        return responses_processed;
    }

    /**
     * Vadidated the received hash against the received fs entry map.
     * @param vpath Virtual path of the fs.
     * @param hash Received hash.
     * @param dir_mode Metadata 'mode' of the directory containing the fs entries.
     * @param peer_fs_entries Received peer fs entries.
     * @returns true if hash is valid, otherwise false.
     */
    bool hpfs_sync::validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const mode_t dir_mode,
                                           const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries)
    {
        util::h32 content_hash;

        const std::string vpath_name = util::get_name(vpath);

        // Initilal hash is vpath hash + mode hash.
        content_hash = crypto::get_hash(vpath_name);

        uint8_t mode_bytes[4];
        util::uint32_to_bytes(mode_bytes, dir_mode);
        content_hash ^= crypto::get_hash(mode_bytes, sizeof(mode_bytes));

        // Then XOR the file hashes to the initial hash.
        for (const p2p::hpfs_fs_hash_entry &fs_entry : peer_fs_entries)
        {
            content_hash ^= fs_entry.hash;
        }

        return content_hash.to_string_view() == hash;
    }

    /**
     * Vadidated the received hash against the received file hash map.
     * @param vpath Virtual path of the file.
     * @param hash Received hash.
     * @param file_mode Metadata 'mode' of the file.
     * @param hashes Received block hashes.
     * @param hash_count Size of the hash list.
     * @returns true if hash is valid, otherwise false.
     */
    bool hpfs_sync::validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const mode_t file_mode,
                                               const util::h32 *hashes, const size_t hash_count)
    {
        util::h32 content_hash = util::h32_empty;

        const std::string vpath_name = util::get_name(vpath);

        // Initilal hash is vpath hash + mode hash.
        content_hash = crypto::get_hash(vpath_name);

        uint8_t mode_bytes[4];
        util::uint32_to_bytes(mode_bytes, file_mode);
        content_hash ^= crypto::get_hash(mode_bytes, sizeof(mode_bytes));

        // Then XOR the block hashes to the initial hash.
        for (size_t block_id = 0; block_id < hash_count; block_id++)
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
        util::h32 hash_calculated = util::h32_empty;
        // If file block 0 buf size 0 means the file is empty, So set hash should be empty.
        if (block_id > 0 || buf.size() > 0)
        {
            const off_t block_offset = block_id * hpfs::BLOCK_SIZE;
            uint8_t bytes[8];
            util::uint64_to_bytes(bytes, block_offset);
            std::string_view offset = std::string_view(reinterpret_cast<const char *>(bytes), sizeof(bytes));
            hash_calculated = crypto::get_hash(offset, buf);
        }
        return hash_calculated.to_string_view() == hash;
    }

    /**
     * Sends a hpfs request to a random peer.
     * @param path Requested file or dir path.
     * @param is_file Whether the requested path if a file or dir.
     * @param block_id The requested block id. Only relevant if requesting a file block. Otherwise -1.
     * @param expected_hash The expected hash of the requested data. The peer will ignore the request if their hash is different.
     * @param target_pubkey The peer pubkey the request was submitted to.
     */
    void hpfs_sync::request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                            const util::h32 expected_hash, std::string &target_pubkey)
    {
        p2p::hpfs_request hr;
        hr.parent_path = path;
        hr.is_file = is_file;
        hr.block_id = block_id;
        hr.expected_hash = expected_hash;
        hr.mount_id = fs_mount->mount_id;

        // Include appropriate hints in the request, so the peer can send pre-emptive responses that are useful to us without having
        // to submit additional requests.
        if (!hr.is_file) // Dir fs entry request.
        {
            // Include fs entry information from our side in the request.
            std::vector<hpfs::child_hash_node> child_hash_nodes;
            fs_mount->get_dir_children_hashes(child_hash_nodes, hpfs::RW_SESSION_NAME, path);

            for (const hpfs::child_hash_node &hn : child_hash_nodes)
                hr.fs_entry_hints.push_back(p2p::hpfs_fs_hash_entry{hn.name, hn.is_file, hn.hash});
        }
        else if (hr.is_file && hr.block_id == -1) // File hash map request.
        {
            // Include file hash map information from our side in the request (file might not exist on our side).
            if (fs_mount->get_file_block_hashes(hr.file_hashmap_hints, hpfs::RW_SESSION_NAME, hr.parent_path) == -1)
                hr.file_hashmap_hints.clear();
        }

        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_hpfs_request(fbuf, hr);
        p2p::send_message_to_random_peer(fbuf, target_pubkey); // todo: send to a node that hold the expected hash to improve reliability of retrieving hpfs state.
    }

    /**
     * Submits a pending hpfs request to the peer.
     * @param request The request to submit and start watching for response.
     * @param watch_only Whether to actually send the request or watch for corresponding response only.
     *                   Used for hint response monitoring.
     * @param is_resubmit Whether this is a request resubmission or not.
     */
    void hpfs_sync::submit_request(const sync_item &request, const bool watch_only, const bool is_resubmit)
    {
        const std::string key = std::string(request.vpath)
                                    .append(reinterpret_cast<const char *>(&request.expected_hash), sizeof(util::h32));
        submitted_requests.try_emplace(key, request);

        if (watch_only)
        {
            LOG_DEBUG << "Hpfs " << name << " sync: Watching response for request. type:" << request.type
                      << " path:" << request.vpath << " block_id:" << request.block_id
                      << " hash:" << request.expected_hash;
        }
        else
        {
            const bool is_file = request.type != SYNC_ITEM_TYPE::DIR;
            std::string target_pubkey;
            request_state_from_peer(request.vpath, is_file, request.block_id, request.expected_hash, target_pubkey);

            LOG_DEBUG << "Hpfs " << name << " sync: " << (is_resubmit ? "Re-submitting" : "Submitting")
                      << " request to [" << (target_pubkey.empty() ? "" : target_pubkey.substr(2, 8)) << "]. type:" << request.type
                      << " path:" << request.vpath << " block_id:" << request.block_id
                      << " hash:" << request.expected_hash;
        }
    }

    /**
     * Process dir children response.
     * @param vpath Virtual path of the fs.
     * @param dir_mode Metadata 'mode' of dir.
     * @param peer_fs_entries Received peer fs entries.
     * @returns 0 on success and no fs write peformed. 1 if write performed. -1 on failure.
     */
    int hpfs_sync::handle_fs_entry_response(std::string_view vpath, const mode_t dir_mode, const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries)
    {
        bool write_performed = false;

        // Create physical directory on our side if not exist.
        std::string parent_physical_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, vpath);
        if (util::create_dir_tree_recursive(parent_physical_path) == -1)
            return -1;

        // Apply physical dir mode if received mode is different from our side.
        const int metadata_res = apply_metadata_mode(parent_physical_path, dir_mode, true);
        if (metadata_res == -1)
            return -1;
        else if (metadata_res == 1)
            write_performed = true;

        for (const p2p::hpfs_fs_hash_entry &entry : peer_fs_entries)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(vpath)
                                          .append(vpath.back() != '/' ? "/" : "")
                                          .append(entry.name);

            if (entry.response_type == p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MISMATCHED)
            {
                // We must request for this entry using the same priority level of the root target.
                const auto target_itr = TARGET_OF_REQUEST(child_vpath);
                if (target_itr != ongoing_targets.end())
                    pending_requests.emplace(sync_item{
                        (entry.is_file ? SYNC_ITEM_TYPE::FILE : SYNC_ITEM_TYPE::DIR), child_vpath, -1, entry.hash, target_itr->high_priority});
                else
                    // We should never hit this error.
                    LOG_ERROR << "Hpfs " << name << " sync: Handle fs entry response: Failed to locate target matching " << vpath;
            }
            else if (entry.response_type == p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::RESPONDED)
            {
                // The peer has already responded with a pre-emptive hint response. So we must start watching for it.
                submit_request(sync_item{entry.is_file ? SYNC_ITEM_TYPE::FILE : SYNC_ITEM_TYPE::DIR, child_vpath, -1, entry.hash}, true);
            }
            else if (entry.response_type == p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::NOT_AVAILABLE)
            {
                // This entry is not available in peer. So we must delete it from our side.
                std::string child_physical_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, child_vpath);

                if ((entry.is_file && unlink(child_physical_path.c_str()) == -1) ||
                    (!entry.is_file && util::remove_directory_recursively(child_physical_path.c_str()) == -1))
                    return -1;

                write_performed = true;
                LOG_DEBUG << "Hpfs " << name << " sync: Deleted " << (entry.is_file ? "file" : "dir") << " path " << child_vpath;
            }
        }

        return write_performed ? 1 : 0;
    }

    /**
     * Process file block hash map response.
     * @param vpath Virtual path of the file.
     * @param file_mode Received metadata mode of the file.
     * @param hashes Received block hashes.
     * @param hash_count No. of received block hashes.
     * @param responded_block_ids List of block ids already responded by the peer.
     * @param file_length Size of the file.
     * @returns 0 on success and no write operation performed. 1 if write opreation peformed. -1 on failure.
     */
    int hpfs_sync::handle_file_hashmap_response(std::string_view vpath, const mode_t file_mode, const util::h32 *hashes, const size_t hash_count,
                                                const std::set<uint32_t> &responded_block_ids, const uint64_t file_length)
    {
        bool write_performed = false;

        // File block hashes on our side (file might not exist on our side).
        std::vector<util::h32> existing_hashes;
        if (fs_mount->get_file_block_hashes(existing_hashes, hpfs::RW_SESSION_NAME, vpath) == -1 && errno != ENOENT)
            return -1;
        const size_t existing_hash_count = existing_hashes.size();

        // Compare the block hashes and request any differences.
        // If responded_block_ids count > 0 and but the hash_count is 0 means this is an empty file. So take the responded_block_ids count.
        const int32_t max_block_id = MAX(existing_hash_count, MAX(hash_count, responded_block_ids.size())) - 1;
        for (int32_t block_id = 0; block_id <= max_block_id; block_id++)
        {
            if (responded_block_ids.count(block_id) == 1)
            {
                // The peer has already responded with a hint response. So we must start watching for it.
                // If file block 0 hash count is 0 means the file is empty, So set hash as empty.
                submit_request(sync_item{SYNC_ITEM_TYPE::BLOCK, std::string(vpath), block_id, (block_id == 0 && hash_count == 0) ? util::h32_empty : hashes[block_id]}, true);
            }
            else if (block_id >= (int32_t)existing_hash_count || existing_hashes[block_id] != hashes[block_id])
            {
                pending_requests.emplace(sync_item{SYNC_ITEM_TYPE::BLOCK, std::string(vpath), block_id, hashes[block_id]});
            }
        }

        if (existing_hashes.size() >= hash_count)
        {
            // If peer file might be smaller, truncate our file to match with peer file.
            std::string file_physical_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, vpath);
            if (truncate(file_physical_path.c_str(), file_length) == -1)
                return -1;

            write_performed = true;
        }

        // Apply physical file mode if received mode is different from our side.
        const std::string physical_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, vpath);
        const int metadata_res = apply_metadata_mode(physical_path, file_mode, false);
        if (metadata_res == -1)
            return -1;
        else if (metadata_res == 1)
            write_performed = true;

        return write_performed ? 1 : 0;
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
        std::string file_physical_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, vpath);
        const int fd = open(file_physical_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << " Open failed " << file_physical_path;
            return -1;
        }

        const off_t offset = block_id * hpfs::BLOCK_SIZE;
        const ssize_t res = pwrite(fd, buf.data(), buf.length(), offset);
        close(fd);
        if (res == -1 || (size_t)res < buf.length())
        {
            LOG_ERROR << errno << " Write failed " << file_physical_path;
            return -1;
        }

        return 0;
    }

    /**
     * Applies the specified to local file/dir if different. If it's a file, this will create the file
     * if not exist.
     * @returns 0 if no change made. 1 if a change was made. -1 on failure.
     */
    int hpfs_sync::apply_metadata_mode(std::string_view physical_path, const mode_t mode, const bool is_dir)
    {
        // Overlay the file/dir type flags to the permission bits.
        const mode_t full_mode = (is_dir ? S_IFDIR : S_IFREG) | mode;

        struct stat st;
        if (stat(physical_path.data(), &st) == -1)
        {
            if (!is_dir && errno == ENOENT) // File does not exist. So we must create it with the given 'mode'.
            {
                // The permissions of a created file are restricted by the process's current umask, so group and world write are always disabled by default.
                // We do the chmod seperatly after mknod the file. Because if we give the g+w permission in mknod() mode param,
                // The file won't get that permission because of the above mentioned default umask.

                if (mknod(physical_path.data(), full_mode, 0) == -1 || chmod(physical_path.data(), mode) == -1)
                {
                    LOG_ERROR << errno << ": Error in creating file node. " << physical_path;
                    return -1;
                }
                else
                {
                    return 1;
                }
            }

            LOG_ERROR << errno << ": Error in stat when applying file/dir mode. " << physical_path;
            return -1;
        }

        // Reaching here means file/dir already exists. So we must apply the specified mode if it's different from current value.
        if (st.st_mode != full_mode)
        {
            if (chmod(physical_path.data(), mode) == -1)
            {
                LOG_ERROR << errno << ": Error in applying file/dir mode. " << physical_path;
                return -1;
            }

            return 1;
        }

        return 0; // No change made.
    }

    /**
     * This method can be used to invoke mount specific custom logic (after overriding this method) to be executed after
     * a sync target is acheived.
     */
    void hpfs_sync::on_sync_target_acheived(const std::string &vpath, const util::h32 &hash)
    {
    }

    /**
     * This method can be used to invoke mount specific custom logic (after overriding this method) to be executed after
     * a sync is abondened.
     */
    void hpfs_sync::on_sync_abandoned()
    {
    }

} // namespace hpfs