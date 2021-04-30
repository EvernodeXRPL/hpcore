#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../util/util.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../ledger/ledger.hpp"
#include "../hplog.hpp"
#include "hpfs_serve.hpp"
#include "hpfs_sync.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

/**
 * Class for serving hpfs requests from other peers.
 */
namespace hpfs
{
    constexpr uint16_t LOOP_WAIT = 20; // Milliseconds
    constexpr const char *HPFS_SESSION_NAME = "rw";
    constexpr uint16_t MAX_HIN_RESPONSES_PER_REQUEST = 3;

    /**
     * @param server_name The name of the serving instance. (For identification purpose)
     * @param fs_mount_ptr The pointer to the relavent hpfs mount instance this server is serving.
     * @return This returns -1 on error and 0 on success.
    */
    int hpfs_serve::init(std::string_view server_name, hpfs::hpfs_mount *fs_mount_ptr)
    {
        if (fs_mount_ptr == NULL)
            return -1;

        name = server_name;
        fs_mount = fs_mount_ptr;

        hpfs_serve_thread = std::thread(&hpfs_serve::hpfs_serve_loop, this);
        init_success = true;
        return 0;
    }

    /**
     * Perform cleanup activities.
    */
    void hpfs_serve::deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;
            hpfs_serve_thread.join();
        }
    }

    void hpfs_serve::hpfs_serve_loop()
    {
        util::mask_signal();

        LOG_INFO << "Hpfs " << name << " server started.";

        // Indicates whether any requests were processed in the previous loop iteration.
        bool prev_requests_processed = false;

        while (!is_shutting_down)
        {
            // Wait a small delay if there were no requests processed during previous iteration.
            if (!prev_requests_processed)
                util::sleep(LOOP_WAIT);

            swap_collected_requests();

            prev_requests_processed = !hpfs_requests.empty();
            const uint64_t time_start = util::get_epoch_milliseconds();
            const p2p::sequence_hash lcl_id = ledger::ctx.get_lcl_id();
            const p2p::sequence_hash last_primary_shard_id = ledger::ctx.get_last_primary_shard_id();
            const uint32_t request_batch_timeout = hpfs::get_request_resubmit_timeout() * 0.9;

            if (hpfs_requests.empty())
                continue;

            if (fs_mount->acquire_rw_session() != -1)
            {
                for (auto &[session_id, hr] : hpfs_requests)
                {
                    if (is_shutting_down)
                        break;

                    // If we have spent too much time handling hpfs requests, abandon the entire batch
                    // because the requester would have stopped waiting for us.
                    const uint64_t time_now = util::get_epoch_milliseconds();
                    if ((time_now - time_start) > request_batch_timeout)
                    {
                        LOG_DEBUG << "Hpfs " << name << " serve batch timeout. Abandonding hpfs requests.";
                        break;
                    }

                    std::vector<flatbuffers::FlatBufferBuilder> fbuf_vec;
                    if (hpfs_serve::generate_sync_responses(fbuf_vec, hr) == 0 && !fbuf_vec.empty())
                    {
                        // Find the peer that we should send the sync responses to.
                        std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
                        const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

                        if (peer_itr != p2p::ctx.peer_connections.end())
                        {
                            comm::comm_session *session = peer_itr->second;

                            for (const flatbuffers::FlatBufferBuilder &fbuf : fbuf_vec)
                            {
                                std::string_view msg = std::string_view(
                                    reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
                                session->send(msg);
                            }
                        }
                    }

                    LOG_DEBUG << "Hpfs " << name << " serve: Sent " << fbuf_vec.size() << " replies to [" << util::to_hex(session_id).substr(2, 10) << "]";
                }

                fs_mount->release_rw_session();
            }

            hpfs_requests.clear();
        }
        LOG_INFO << "Hpfs " << name << " server stopped.";
    }

    /**
     * Creates reply messages for a given hpfs sync request.
     * @param fbuf_vec List of flatbuffer builders containing the generated reply messages.
     * @param hr The hpfs request which should be replied to.
     * @return 0 on success. -1 on error.
     */
    int hpfs_serve::generate_sync_responses(std::vector<flatbuffers::FlatBufferBuilder> &fbuf_vec, const p2p::hpfs_request &hr)
    {
        LOG_DEBUG << "Serving hpfs req. path:" << hr.parent_path << " block_id:" << hr.block_id;

        // If block_id > -1 this means this is a file block data request.
        if (hr.block_id > -1)
        {
            // Vector to hold the block bytes. Normally block size is constant BLOCK_SIZE (4MB), but the
            // last block of a file may have a smaller size.
            std::vector<uint8_t> block;
            const int result = get_data_block_with_hash_check(block, hr.parent_path, hr.block_id, hr.expected_hash);

            if (result == -1)
            {
                LOG_ERROR << "Error in getting file block: " << hr.parent_path;
                return -1;
            }
            else if (result == 1)
            {
                fbuf_vec.push_back(flatbuffers::FlatBufferBuilder());
                p2pmsg::create_msg_from_block_response(fbuf_vec.back(), hr.block_id, block, hr.expected_hash, hr.parent_path, fs_mount->mount_id);
            }
        }
        else
        {
            // File hpfs request means we have to reply with the file block hash map.
            if (hr.is_file)
            {
                std::vector<util::h32> block_hashes;
                size_t file_length = 0;
                mode_t file_mode = 0;
                const int result = get_data_block_hashes_with_hash_check(block_hashes, file_length, file_mode, hr.parent_path, hr.expected_hash);

                if (result == -1)
                {
                    LOG_ERROR << "Error in getting block hashes: " << hr.parent_path;
                    return -1;
                }
                else if (result == 1)
                {
                    fbuf_vec.push_back(flatbuffers::FlatBufferBuilder());
                    p2pmsg::create_msg_from_filehashmap_response(
                        fbuf_vec.back(), hr.parent_path, fs_mount->mount_id, block_hashes,
                        file_length, file_mode, hr.expected_hash);
                }
            }
            else
            {
                // If the hpfs request is for a directory we need to reply with the
                // file system entries and their hashes inside that dir.
                std::vector<p2p::hpfs_fs_hash_entry> fs_entries;
                const int result = get_fs_entry_hashes_with_hash_check(fs_entries, hr.parent_path, hr.expected_hash);

                if (result == -1)
                {
                    LOG_ERROR << "Error in getting fs entries: " << hr.parent_path;
                    return -1;
                }
                else if (result == 1)
                {
                    // Get dir mode.
                    const std::string dir_path = fs_mount->rw_dir + hr.parent_path.data();
                    struct stat st;
                    if (stat(dir_path.data(), &st) == -1)
                    {
                        LOG_ERROR << errno << ": Error in getting dir metadata: " << hr.parent_path;
                        return -1;
                    }

                    std::vector<p2p::hpfs_fs_hash_entry> respond_fs_entries;
                    generate_reply_fs_entries(fs_entries, respond_fs_entries, hr.fs_entry_hints);

                    // Generate parent reply.
                    fbuf_vec.push_back(flatbuffers::FlatBufferBuilder());
                    p2pmsg::create_msg_from_fsentry_response(
                        fbuf_vec.back(), hr.parent_path, fs_mount->mount_id, st.st_mode, fs_entries, hr.expected_hash);

                    for (const p2p::hpfs_fs_hash_entry &entry : respond_fs_entries)
                    {
                        std::string vpath = hr.parent_path + "/" + entry.name;
                        if (entry.is_file)
                        {
                            std::vector<util::h32> block_hashes;
                            size_t file_length = 0;
                            mode_t file_mode = 0;
                            if (get_data_block_hashes(block_hashes, file_length, file_mode, vpath) != -1)
                            {
                                fbuf_vec.push_back(flatbuffers::FlatBufferBuilder());
                                p2pmsg::create_msg_from_filehashmap_response(
                                    fbuf_vec.back(), vpath, fs_mount->mount_id, block_hashes,
                                    file_length, file_mode, entry.hash);
                            }
                        }
                        else
                        {
                            std::vector<p2p::hpfs_fs_hash_entry> fs_entries;
                            const int result = get_fs_entry_hashes_with_hash_check(fs_entries, vpath, entry.hash);

                            fbuf_vec.push_back(flatbuffers::FlatBufferBuilder());
                            p2pmsg::create_msg_from_fsentry_response(
                                fbuf_vec.back(), hr.parent_path, fs_mount->mount_id, st.st_mode, fs_entries, hr.expected_hash);
                        }
                    }
                }
            }
        }

        return 0;
    }

    void hpfs_serve::generate_reply_fs_entries(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries, std::vector<p2p::hpfs_fs_hash_entry> &respond_fs_entries,
                                               const std::vector<p2p::hpfs_fs_hash_entry> &fs_entry_hints)
    {
        // Prepare hint map to provide match comparisons based on hints.
        std::map<std::string, p2p::hpfs_fs_hash_entry> hint_fs_entry_map;
        for (const p2p::hpfs_fs_hash_entry &hint : fs_entry_hints)
            hint_fs_entry_map.emplace(hint.name, std::move(hint));

        for (p2p::hpfs_fs_hash_entry &entry : fs_entries)
        {
            // Check with provided hints to include match information.
            const auto itr = hint_fs_entry_map.find(entry.name);
            if (itr != hint_fs_entry_map.end()) // fs entry exists on both sides.
            {
                const p2p::hpfs_fs_hash_entry &hint = itr->second;
                if (hint.hash == entry.hash)
                {
                    entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MATCHED;
                }
                else // Hash not matching. Sync needed.
                {
                    if (respond_fs_entries.size() < MAX_HIN_RESPONSES_PER_REQUEST)
                    {
                        entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::RESPONDED;
                        respond_fs_entries.push_back(entry);
                    }
                    else
                    {
                        entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MISMATCHED;
                    }
                }

                // Remove the entry from the hint list so at the end, the hint map will only cotain children we don't possess on our side.
                hint_fs_entry_map.erase(entry.name);
            }
            else // fs entry only exists on our side.
            {
                if (respond_fs_entries.size() < MAX_HIN_RESPONSES_PER_REQUEST)
                {
                    entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::RESPONDED;
                    respond_fs_entries.push_back(entry);
                }
                else
                {
                    entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::AVAILABLE;
                }
            }
        }

        // Take the reamainig entries in the hint list and include them in the fs entry response as not exist.
        // When the requester sees this, they will remove those entries from their side.
        for (const auto &[name, hint] : hint_fs_entry_map)
            fs_entries.push_back(p2p::hpfs_fs_hash_entry{name, hint.is_file, util::h32_empty, p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::NOT_AVAILABLE});
    }

    /**
     * Retrieves the specified data block from a hpfs file if expected hash matches.
     * @return 1 if block data was succefully fetched. 0 if vpath or block does not exist. -1 on error.
     */
    int hpfs_serve::get_data_block_with_hash_check(std::vector<uint8_t> &block, const std::string_view vpath,
                                                   const uint32_t block_id, const util::h32 expected_hash)
    {
        // Check whether the existing block hash matches expected hash.
        std::vector<util::h32> block_hashes;
        int result = fs_mount->get_file_block_hashes(block_hashes, HPFS_SESSION_NAME, vpath);
        if (result == 1)
        {
            if (block_id >= block_hashes.size())
            {
                LOG_DEBUG << "Requested block_id " << block_id << " does not exist.";
                result = 0;
            }
            else if (block_hashes[block_id] != expected_hash)
            {
                LOG_DEBUG << "Expected hash mismatch.";
                result = 0;
            }
            else // Get actual block data.
            {
                if (get_data_block(block, vpath, block_id) == -1)
                    result = -1;
                else
                    result = 1; // Success.
            }
        }

        return result;
    }

    /**
     * Retrieves the specified file block hashes if expected hash matches.
     * @return 1 if block hashes were successfuly fetched. 0 if hash mismatch. -1 on error.
     */
    int hpfs_serve::get_data_block_hashes_with_hash_check(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode,
                                                          const std::string_view vpath, const util::h32 expected_hash)
    {
        // Check whether the existing file hash matches expected hash.
        util::h32 file_hash = util::h32_empty;
        int result = fs_mount->get_hash(file_hash, HPFS_SESSION_NAME, vpath);
        if (result == 1)
        {
            if (file_hash != expected_hash)
            {
                LOG_DEBUG << "Expected hash mismatch.";
                result = 0;
            }
            else
            {
                if (get_data_block_hashes(hashes, file_length, file_mode, vpath) == -1)
                    result = -1;
                else
                    result = 1; // Success.
            }
        }

        return result;
    }

    /**
     * Retrieves the specified dir entry hashes if expected fir hash matches.
     * @return 1 if fs entry hashes were successfuly fetched. 0 if vpath does not exist. -1 on error.
     */
    int hpfs_serve::get_fs_entry_hashes_with_hash_check(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries,
                                                        const std::string_view vpath, const util::h32 expected_hash)
    {
        // Check whether the existing dir hash matches expected hash.
        util::h32 dir_hash = util::h32_empty;
        int result = fs_mount->get_hash(dir_hash, HPFS_SESSION_NAME, vpath);
        if (result == 1)
        {
            if (dir_hash != expected_hash)
            {
                LOG_DEBUG << "Expected hash mismatch.";
                result = 0;
            }
            // Get the children hash nodes.
            else if (get_fs_entry_hashes(fs_entries, vpath) < 0)
            {
                result = -1;
            }
            else
            {
                result = 1; // Success.
            }
        }

        return result;
    }

    /**
     * Fetches the specified file data block.
     * @return 0 on success. -1 on error.
     */
    int hpfs_serve::get_data_block(std::vector<uint8_t> &block, const std::string_view vpath, const uint32_t block_id)
    {
        struct stat st;
        const std::string file_path = fs_mount->rw_dir + vpath.data();
        const off_t block_offset = block_id * hpfs::BLOCK_SIZE;
        const int fd = open(file_path.c_str(), O_RDONLY | O_CLOEXEC);

        if (fd == -1)
        {
            LOG_ERROR << errno << ": Open failed " << file_path;
            return -1;
        }

        int result = 0;
        if (fstat(fd, &st) == -1)
        {
            LOG_ERROR << errno << ": Stat failed. " << file_path;
            result = -1;
        }
        else if (!S_ISREG(st.st_mode))
        {
            LOG_ERROR << "Not a file. " << file_path;
            result = -1;
        }
        else if (block_offset > st.st_size)
        {
            LOG_ERROR << "Block offset " << block_offset << " larger than file " << st.st_size << " - " << file_path;
            result = -1;
        }
        else
        {
            const size_t read_len = MIN(hpfs::BLOCK_SIZE, (st.st_size - block_offset));
            block.resize(read_len);

            lseek(fd, block_offset, SEEK_SET);
            const int res = read(fd, block.data(), read_len);
            if (res < read_len)
            {
                LOG_ERROR << errno << ": Read failed (result:" << res
                          << " off:" << block_offset << " len:" << read_len << "). " << file_path;
                result = -1;
            }
            else
            {
                result = 0; // Success.
            }
        }

        close(fd);
        return result;
    }

    /**
     * Fetches the file data block hash list.
     * @return 0 on success. -1 on error.
     */
    int hpfs_serve::get_data_block_hashes(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode, const std::string_view vpath)
    {
        // Get the block hashes.
        if (fs_mount->get_file_block_hashes(hashes, HPFS_SESSION_NAME, vpath) < 0)
        {
            return -1;
        }
        else
        {
            // Get actual file metadata.
            const std::string file_path = fs_mount->rw_dir + vpath.data();
            struct stat st;
            if (stat(file_path.c_str(), &st) == -1)
            {
                LOG_ERROR << errno << ": Stat failed when getting file metadata. " << file_path;
                return -1;
            }
            file_length = st.st_size;
            file_mode = st.st_mode;
            return 0;
        }
    }

    /**
     * Populates the list of dir entry hashes for the specified vpath.
     * @return 1 on success. 0 if vpath not found. -1 on error.
     */
    int hpfs_serve::get_fs_entry_hashes(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries, const std::string_view vpath)
    {
        std::vector<hpfs::child_hash_node> child_hash_nodes;
        int res = fs_mount->get_dir_children_hashes(child_hash_nodes, HPFS_SESSION_NAME, vpath);
        if (res > 0)
        {
            for (const hpfs::child_hash_node &hn : child_hash_nodes)
                fs_entries.push_back(p2p::hpfs_fs_hash_entry{hn.name, hn.is_file, hn.hash});
        }

        return res;
    }

} // namespace hpfs