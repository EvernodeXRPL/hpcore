#include "../state/state_sync.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../cons/cons.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../hpfs/hpfs.hpp"
#include "../hpfs/h32.hpp"

namespace state_sync
{
    // Idle loop sleep time  (milliseconds).
    constexpr uint16_t IDLE_WAIT = 50;

    // Max number of requests that can be awaiting response at any given time.
    constexpr uint16_t MAX_AWAITING_REQUESTS = 1;

    // Request loop sleep time (milliseconds).
    constexpr uint16_t REQUEST_LOOP_WAIT = 20;

    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB;

    constexpr int FILE_PERMS = 0644;

    // No. of milliseconds to wait before resubmitting a request.
    uint16_t REQUEST_RESUBMIT_TIMEOUT;

    sync_context ctx;

    int init()
    {
        REQUEST_RESUBMIT_TIMEOUT = conf::cfg.roundtime / 2;
        ctx.target_state = hpfs::h32_empty;
        ctx.state_sync_thread = std::thread(state_syncer_loop);
        return 0;
    }

    void deinit()
    {
        ctx.is_syncing = false;
        ctx.is_shutting_down = true;
        ctx.state_sync_thread.join();
    }

    /**
 * Initiates state sync process by setting up context variables and sending the initial state request.
 * @param target_state The target state which we should sync towards.
 */
    void sync_state(const hpfs::h32 target_state)
    {
        std::lock_guard<std::mutex> lock(ctx.target_update_lock);

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
                std::lock_guard<std::mutex> lock(ctx.target_update_lock);
                if (!ctx.is_syncing)
                    continue;

                LOG_INFO << "State sync: Starting sync for target state: " << ctx.target_state;
            }

            LOG_DBG << "State sync: Starting hpfs rw session...";
            pid_t hpfs_pid = 0;
            if (hpfs::start_fs_session(hpfs_pid, ctx.hpfs_mount_dir, "rw", true) != -1)
            {
                while (!ctx.is_shutting_down)
                {
                    hpfs::h32 new_state = hpfs::h32_empty;
                    request_loop(ctx.target_state, new_state);

                    if (ctx.is_shutting_down)
                        break;

                    ctx.pending_requests.clear();

                    {
                        std::lock_guard<std::mutex> lock(ctx.target_update_lock);
                        cons::ctx.state = new_state;

                        if (new_state == ctx.target_state)
                        {
                            LOG_INFO << "State sync: Target state achieved: " << ctx.target_state;
                            ctx.candidate_state_responses.clear();
                            ctx.submitted_requests.clear();
                            break;
                        }
                        else
                        {
                            LOG_INFO << "State sync: Continuing sync for new target: " << ctx.target_state;
                            continue;
                        }
                    }
                }

                // Stop hpfs rw session.
                LOG_DBG << "State sync: Stopping hpfs session... pid:" << hpfs_pid;
                util::kill_process(hpfs_pid, true);
            }
            else
            {
                LOG_ERR << "State sync: Failed to start hpfs rw session";
            }

            ctx.target_state = hpfs::h32_empty;
            ctx.is_syncing = false;
        }

        LOG_INFO << "State sync: Worker stopped.";
    }

    void request_loop(const hpfs::h32 current_target, hpfs::h32 &updated_state)
    {
        // Send the initial root state request.
        submit_request(backlog_item{BACKLOG_ITEM_TYPE::DIR, "/", -1, current_target});

        while (!should_stop_request_loop(current_target))
        {
            util::sleep(REQUEST_LOOP_WAIT);

            {
                std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);

                // Move collected state responses over to local candidate responses list.
                if (!p2p::ctx.collected_msgs.state_response.empty())
                    ctx.candidate_state_responses.splice(ctx.candidate_state_responses.end(), p2p::ctx.collected_msgs.state_response);
            }

            for (auto &response : ctx.candidate_state_responses)
            {
                if (should_stop_request_loop(current_target))
                    return;

                const fbschema::p2pmsg::Content *content = fbschema::p2pmsg::GetContent(response.data());
                const fbschema::p2pmsg::State_Response_Message *resp_msg = content->message_as_State_Response_Message();

                // Check whether we are actually waiting for this response's hash. If not, ignore it.
                const hpfs::h32 response_hash = fbschema::flatbuff_bytes_to_hash(resp_msg->hash());
                const auto pending_resp_itr = ctx.submitted_requests.find(response_hash);
                if (pending_resp_itr == ctx.submitted_requests.end())
                {
                    LOG_DBG << "Skipping state response due to hash mismatch. Received:" << response_hash;
                    continue;
                }

                // Now that we have received matching hash, remove it from the waiting list.
                ctx.submitted_requests.erase(pending_resp_itr);

                // Process the message based on response type.
                const fbschema::p2pmsg::State_Response msg_type = resp_msg->state_response_type();

                if (msg_type == fbschema::p2pmsg::State_Response_Fs_Entry_Response)
                    handle_fs_entry_response(resp_msg->state_response_as_Fs_Entry_Response());
                else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
                    handle_file_hashmap_response(resp_msg->state_response_as_File_HashMap_Response());
                else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
                    handle_file_block_response(resp_msg->state_response_as_Block_Response());

                // After handling each response, check whether we have reached target state.
                hpfs::get_hash(updated_state, ctx.hpfs_mount_dir, "/");
                LOG_DBG << "State sync: current:" << updated_state << " | target:" << current_target;
                if (updated_state == current_target)
                   return;
            }

            ctx.candidate_state_responses.clear();

            // Check for long-awaited responses and re-request them.
            for (auto &[hash, request] : ctx.submitted_requests)
            {
                if (should_stop_request_loop(current_target))
                    return;

                if (request.waiting_time < REQUEST_RESUBMIT_TIMEOUT)
                {
                    // Increment wait time.
                    request.waiting_time += REQUEST_LOOP_WAIT;
                }
                else
                {
                    // Reset the counter and re-submit request.
                    request.waiting_time = 0;
                    LOG_DBG << "State sync: Resubmitting request...";
                    submit_request(request);
                }
            }

            // Check whether we can submit any more requests.
            if (!ctx.pending_requests.empty() && ctx.submitted_requests.size() < MAX_AWAITING_REQUESTS)
            {
                const uint16_t available_slots = MAX_AWAITING_REQUESTS - ctx.submitted_requests.size();
                for (int i = 0; i < available_slots && !ctx.pending_requests.empty(); i++)
                {
                    if (should_stop_request_loop(current_target))
                        return;

                    const backlog_item &request = ctx.pending_requests.front();
                    submit_request(request);
                    ctx.pending_requests.pop_front();
                }
            }
        }
    }

    /**
 * Indicates whether to break out of state request processing loop.
 */
    bool should_stop_request_loop(const hpfs::h32 current_target)
    {
        if (ctx.is_shutting_down)
            return true;

        // Stop request loop if the target has changed.
        std::lock_guard<std::mutex> lock(ctx.target_update_lock);
        return current_target != ctx.target_state;
    }

    /**
 * Sends a state request to a random peer.
 * @param path Requested file or dir path.
 * @param is_file Whether the requested path if a file or dir.
 * @param block_id The requested block id. Only relevant if requesting a file block. Otherwise -1.
 * @param expected_hash The expected hash of the requested data. The peer will ignore the request if their hash is different.
 */
    void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id, const hpfs::h32 expected_hash)
    {
        p2p::state_request sr;
        sr.parent_path = path;
        sr.is_file = is_file;
        sr.block_id = block_id;
        sr.expected_hash = expected_hash;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        fbschema::p2pmsg::create_msg_from_state_request(fbuf, sr, cons::ctx.lcl);
        p2p::send_message_to_random_peer(fbuf); //todo: send to a node that hold the majority state to improve reliability of retrieving state.
    }

    /**
 * Submits a pending state request to the peer.
 */
    void submit_request(const backlog_item &request)
    {
        LOG_DBG << "State sync: Submitting request. type:" << request.type
                << " path:" << request.path << " block_id:" << request.block_id
                << " hash:" << request.expected_hash;

        ctx.submitted_requests.try_emplace(request.expected_hash, request);

        const bool is_file = request.type != BACKLOG_ITEM_TYPE::DIR;
        request_state_from_peer(request.path, is_file, request.block_id, request.expected_hash);
    }

    /**
 * Process dir children response.
 */
    int handle_fs_entry_response(const fbschema::p2pmsg::Fs_Entry_Response *fs_entry_resp)
    {
        // Get the parent path of the fs entries we have received.
        std::string_view parent_vpath = fbschema::flatbuff_str_to_sv(fs_entry_resp->path());
        LOG_DBG << "State sync: Processing fs entries response for " << parent_vpath;

        // Get fs entries we have received.
        std::unordered_map<std::string, p2p::state_fs_hash_entry> peer_fs_entry_map;
        fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(peer_fs_entry_map, fs_entry_resp->entries());

        // Create physical directory on our side if not exist.
        std::string parent_physical_path = std::string(ctx.hpfs_mount_dir).append(parent_vpath);
        if (util::create_dir_tree_recursive(parent_physical_path) == -1)
            return -1;

        // Get the children hash entries and compare with what we got from peer.
        std::vector<hpfs::child_hash_node> existing_fs_entries;
        if (hpfs::get_dir_children_hashes(existing_fs_entries, ctx.hpfs_mount_dir, parent_vpath) == -1)
            return -1;

        // Request more info on fs entries that exist on both sides but are different.
        for (const auto &ex_entry : existing_fs_entries)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(parent_vpath)
                                          .append(parent_vpath.back() != '/' ? "/" : "")
                                          .append(ex_entry.name);

            const auto peer_itr = peer_fs_entry_map.find(ex_entry.name);
            if (peer_itr != peer_fs_entry_map.end())
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

                peer_fs_entry_map.erase(peer_itr);
            }
            else
            {
                // If there was an entry that does not exist on other side, delete it.
                std::string child_physical_path = std::string(ctx.hpfs_mount_dir).append(child_vpath);

                if ((ex_entry.is_file && unlink(child_physical_path.c_str()) == -1) ||
                    !ex_entry.is_file && rmdir(child_physical_path.c_str()) == -1)
                    return -1;

                LOG_DBG << "State sync: Deleted " << (ex_entry.is_file ? "file" : "dir") << " path " << child_vpath;
            }
        }

        // Queue the remaining peer fs entries (that our side does not have at all) to request.
        for (const auto &[name, fs_entry] : peer_fs_entry_map)
        {
            // Construct child vpath.
            std::string child_vpath = std::string(parent_vpath)
                                          .append(parent_vpath.back() != '/' ? "/" : "")
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
 */
    int handle_file_hashmap_response(const fbschema::p2pmsg::File_HashMap_Response *file_resp)
    {
        // Get the file path of the block hashes we have received.
        std::string file_vpath = std::string(fbschema::flatbuff_str_to_sv(file_resp->path()));
        LOG_DBG << "State sync: Processing file block hashes response for " << file_vpath;

        // File block hashes on our side (file might not exist on our side).
        std::vector<hpfs::h32> existing_hashes;
        if (hpfs::get_file_block_hashes(existing_hashes, ctx.hpfs_mount_dir, file_vpath) == -1 && errno != ENOENT)
            return -1;
        const size_t existing_hash_count = existing_hashes.size();

        // File block hashes we received from the peer.
        const hpfs::h32 *peer_hashes = reinterpret_cast<const hpfs::h32 *>(file_resp->hash_map()->data());
        const size_t peer_hash_count = file_resp->hash_map()->size() / sizeof(hpfs::h32);

        // Compare the block hashes and request any differences.
        auto insert_itr = ctx.pending_requests.begin();
        const int32_t max_block_id = MAX(existing_hash_count, peer_hash_count) - 1;
        for (int32_t block_id = 0; block_id <= max_block_id; block_id++)
        {
            // Insert at front to give priority to block requests while preserving block order.
            if (block_id >= existing_hash_count || existing_hashes[block_id] != peer_hashes[block_id])
                ctx.pending_requests.insert(insert_itr, backlog_item{BACKLOG_ITEM_TYPE::BLOCK, file_vpath, block_id, peer_hashes[block_id]});
        }

        if (existing_hashes.size() >= peer_hash_count)
        {
            // If peer file might be smaller, truncate our file to match with peer file.
            std::string file_physical_path = std::string(ctx.hpfs_mount_dir).append(file_vpath);
            if (truncate(file_physical_path.c_str(), file_resp->file_length()) == -1)
                return -1;
        }

        return 0;
    }

    /**
 * Process file block response.
 */
    int handle_file_block_response(const fbschema::p2pmsg::Block_Response *block_msg)
    {
        // Get the file path of the block data we have received.
        std::string_view file_vpath = fbschema::flatbuff_str_to_sv(block_msg->path());
        const uint32_t block_id = block_msg->block_id();
        std::string_view buf = fbschema::flatbuff_bytes_to_sv(block_msg->data());

        LOG_DBG << "State sync: Writing block_id " << block_id
                << " (len:" << buf.length()
                << ") of " << file_vpath;

        std::string file_physical_path = std::string(ctx.hpfs_mount_dir).append(file_vpath);
        const int fd = open(file_physical_path.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERR << errno << " Open failed " << file_physical_path;
            return -1;
        }

        const off_t offset = block_id * BLOCK_SIZE;
        const int res = pwrite(fd, buf.data(), buf.length(), offset);
        close(fd);
        if (res < buf.length())
        {
            LOG_ERR << errno << " Write failed " << file_physical_path;
            return -1;
        }

        return 0;
    }

} // namespace state_sync