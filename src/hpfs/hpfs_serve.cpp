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
 * Class for serving hpfs sync requests from other peers.
 */
namespace hpfs
{
    constexpr uint16_t LOOP_WAIT = 20; // Milliseconds
    constexpr const char *HPFS_SESSION_NAME = "rw";
    constexpr uint16_t MAX_HASHMAP_RESPONSES_PER_REQUEST = 4;
    constexpr uint16_t MAX_BLOCK_RESPONSES_PER_REQUEST = 1;

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

                    std::list<flatbuffers::FlatBufferBuilder> fbufs;
                    if (hpfs_serve::generate_sync_responses(fbufs, hr) == 0 && !fbufs.empty())
                    {
                        // Find the peer that we should send the sync responses to.
                        std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
                        const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

                        if (peer_itr != p2p::ctx.peer_connections.end())
                        {
                            comm::comm_session *session = peer_itr->second;

                            for (const flatbuffers::FlatBufferBuilder &fbuf : fbufs)
                            {
                                std::string_view msg = std::string_view(
                                    reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
                                session->send(msg);
                            }
                        }
                    }

                    LOG_DEBUG << "Hpfs " << name << " serve: Sent " << fbufs.size() << " replies to [" << util::to_hex(session_id).substr(2, 10) << "]";
                }

                fs_mount->release_rw_session();
            }

            hpfs_requests.clear();
        }
        LOG_INFO << "Hpfs " << name << " server stopped.";
    }

    /**
     * Creates reply messages for a given hpfs sync request.
     * @param fbufs List of flatbuffer builders containing the generated reply messages.
     * @param hr The hpfs request which should be replied to.
     * @return 0 on success. -1 on error.
     */
    int hpfs_serve::generate_sync_responses(std::list<flatbuffers::FlatBufferBuilder> &fbufs, const p2p::hpfs_request &hr)
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
                p2pmsg::create_msg_from_block_response(fbufs.emplace_back(), hr.block_id, block, hr.expected_hash, hr.parent_path, fs_mount->mount_id);
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
                const int result = get_file_block_hashes_with_hash_check(block_hashes, file_length, file_mode, hr.parent_path, hr.expected_hash);

                if (result == -1)
                {
                    LOG_ERROR << "Error in getting block hashes: " << hr.parent_path;
                    return -1;
                }
                else if (result == 1)
                {
                    // By looking at the block hashmap hints the requester has provided, we also include pre-emptive data block responses
                    // that the requester needs.
                    std::vector<uint32_t> responded_block_ids;
                    for (uint32_t block_id = 0; block_id < block_hashes.size(); block_id++)
                    {
                        if (responded_block_ids.size() < MAX_BLOCK_RESPONSES_PER_REQUEST &&
                            (hr.file_hashmap_hints.size() <= block_id || hr.file_hashmap_hints[block_id] != block_hashes[block_id]))
                        {
                            std::vector<uint8_t> block;
                            if (get_data_block(block, hr.parent_path, block_id) != -1)
                            {
                                p2pmsg::create_msg_from_block_response(fbufs.emplace_back(), block_id, block, block_hashes[block_id], hr.parent_path, fs_mount->mount_id);
                                responded_block_ids.push_back(block_id);

                                if (responded_block_ids.size() == MAX_BLOCK_RESPONSES_PER_REQUEST)
                                    break;
                            }
                        }
                    }

                    // Generate parent reply. We must insert it at the begning of replies.
                    // This is the reply the requester originally requested. But we also indicate in it any pre-emptive hint responses
                    // we are sending along with it.
                    p2pmsg::create_msg_from_filehashmap_response(
                        fbufs.emplace_front(), hr.parent_path, fs_mount->mount_id, block_hashes,
                        responded_block_ids, file_length, file_mode, hr.expected_hash);
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
                    const std::string dir_path = fs_mount->physical_path(HPFS_SESSION_NAME, hr.parent_path);
                    struct stat st;
                    if (stat(dir_path.data(), &st) == -1)
                    {
                        LOG_ERROR << errno << ": Error in getting dir metadata: " << hr.parent_path;
                        return -1;
                    }

                    // By looking at the fs entry hints the requester has provided, we also include pre-emptive hashmap and data block
                    // responses that the requester needs.
                    generate_fs_entry_hint_responses(fbufs, fs_entries, hr.fs_entry_hints, hr.parent_path);

                    // Generate parent reply. We must insert it at the begning of replies.
                    // This is the reply the requester originally requested. But we also indicate in it any pre-emptive hint responses
                    // we are sending along with it. In this case, the 'fs entries' we are replying with are already marked as having an
                    // accompanying pre-emptive hint response.
                    p2pmsg::create_msg_from_fsentry_response(
                        fbufs.emplace_front(), hr.parent_path, fs_mount->mount_id, st.st_mode, fs_entries, hr.expected_hash);
                }
            }
        }

        return 0;
    }

    /**
     * Generates flatbuffer messages for any pre-emptive hint responses that we should send according to the fs entry hints provided by the requester.
     * @param fbufs The flatbuffer message list to populate with hint responses.
     * @param fs_entries The fs entry collection that is going to be sent with the parent fs entry reply.
     * @param fs_entry_hints The fs entry hints the requester has provided.
     * @param parent_path The vpath of the parent directory which contains the fs entries.
     */
    void hpfs_serve::generate_fs_entry_hint_responses(std::list<flatbuffers::FlatBufferBuilder> &fbufs, std::vector<p2p::hpfs_fs_hash_entry> &fs_entries,
                                                      const std::vector<p2p::hpfs_fs_hash_entry> &fs_entry_hints, std::string_view parent_vpath)
    {
        // Counters tracking how many pre-emptive hint responses of each type we have generated so far.
        size_t hashmap_responses = 0;
        size_t block_responses = 0;

        // Prepare hint map to provide match comparisons based on hints provided by the requester.
        std::map<std::string, p2p::hpfs_fs_hash_entry> hint_fs_entry_map;
        for (const p2p::hpfs_fs_hash_entry &hint : fs_entry_hints)
            hint_fs_entry_map.emplace(hint.name, std::move(hint));

        // For each fs entry we are replying with, look for the possibilty of generating hint responses.
        for (p2p::hpfs_fs_hash_entry &entry : fs_entries)
        {
            // Check with provided hints to include match information.
            const auto itr = hint_fs_entry_map.find(entry.name);
            // Whether fs entry exists on the requesting party.
            const bool exists_on_requester = itr != hint_fs_entry_map.end();

            // Remove the entry from the hint list so at the end, the hint map will only contain children we don't possess on our side.
            if (exists_on_requester)
                hint_fs_entry_map.erase(entry.name);

            entry.response_type = (exists_on_requester && itr->second.hash == entry.hash) ? p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MATCHED : p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MISMATCHED;

            // Send hashmap hint response if we haven't reached the limit.
            const bool send_hashmap_response = (entry.response_type == p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::MISMATCHED) && (hashmap_responses < MAX_HASHMAP_RESPONSES_PER_REQUEST);
            if (!send_hashmap_response)
                continue;

            // Reaching this point means we have to generate the hashmap hint response along with the parent fs entry reply.

            std::string child_vpath = std::string(parent_vpath)
                                          .append(parent_vpath.back() != '/' ? "/" : "")
                                          .append(entry.name);
            if (entry.is_file)
            {
                std::vector<util::h32> block_hashes;
                size_t file_length = 0;
                mode_t file_mode = 0;
                if (get_file_block_hashes(block_hashes, file_length, file_mode, child_vpath) != -1)
                {
                    std::vector<uint32_t> responded_block_ids;

                    // Can additionally send block data hint response for block 0, if we know that the entire file does not exist on other side.
                    const bool send_block_response = !exists_on_requester && block_responses < MAX_BLOCK_RESPONSES_PER_REQUEST;
                    if (send_block_response)
                    {
                        std::vector<uint8_t> block;
                        if (get_data_block(block, child_vpath, 0) != -1)
                        {
                            p2pmsg::create_msg_from_block_response(fbufs.emplace_back(), 0, block, block_hashes[0], child_vpath, fs_mount->mount_id);
                            block_responses++;
                            responded_block_ids.push_back(0);
                        }
                    }

                    // If block response already inserted, we must insert hashmap response before that. This is because the hint resposnes must be
                    // sent in the logical dependency order. In this case, the hashmap hint response will indicate to the requester of any pre-emptive
                    // block data responses we are sending. Therefore, block data hint response must follow the hashmap hint response.
                    auto pos = fbufs.end();
                    if (!responded_block_ids.empty())
                        pos--;
                    p2pmsg::create_msg_from_filehashmap_response(
                        *fbufs.emplace(pos), child_vpath, fs_mount->mount_id, block_hashes,
                        responded_block_ids, file_length, file_mode, entry.hash);

                    entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::RESPONDED;
                    hashmap_responses++;
                }
            }
            else // Is dir.
            {
                // This is a directory, generate an fs entry resposne for that directory.
                std::vector<p2p::hpfs_fs_hash_entry> fs_entries;
                if (get_fs_entry_hashes(fs_entries, child_vpath) > 0)
                {
                    struct stat st;
                    if (stat(child_vpath.data(), &st) == -1)
                    {
                        LOG_ERROR << errno << ": Error in getting dir metadata: " << child_vpath;
                    }
                    else
                    {
                        p2pmsg::create_msg_from_fsentry_response(
                            fbufs.emplace_back(), child_vpath, fs_mount->mount_id, st.st_mode, fs_entries, entry.hash);

                        entry.response_type = p2p::HPFS_FS_ENTRY_RESPONSE_TYPE::RESPONDED;
                        hashmap_responses++;
                    }
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
    int hpfs_serve::get_file_block_hashes_with_hash_check(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode,
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
                if (get_file_block_hashes(hashes, file_length, file_mode, vpath) == -1)
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
        const std::string file_path = fs_mount->physical_path(HPFS_SESSION_NAME, vpath);
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
    int hpfs_serve::get_file_block_hashes(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode, const std::string_view vpath)
    {
        // Get the block hashes.
        if (fs_mount->get_file_block_hashes(hashes, HPFS_SESSION_NAME, vpath) < 0)
        {
            return -1;
        }
        else
        {
            // Get actual file metadata.
            const std::string file_path = fs_mount->physical_path(HPFS_SESSION_NAME, vpath);
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