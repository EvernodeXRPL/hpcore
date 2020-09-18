#include "../pchheader.hpp"
#include "../hpfs/hpfs.hpp"
#include "../hpfs/h32.hpp"
#include "../util.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../cons/cons.hpp"
#include "../hplog.hpp"
#include "state_serve.hpp"
#include "state_common.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

/**
 * Helper functions for serving state requests from other peers.
 */
namespace state_serve
{
    constexpr uint16_t LOOP_WAIT = 100; // Milliseconds

    uint16_t REQUEST_BATCH_TIMEOUT;

    bool is_shutting_down = false;
    bool init_success = false;
    std::thread state_serve_thread;

    int init()
    {
        REQUEST_BATCH_TIMEOUT = state_common::get_request_resubmit_timeout() * 0.9;
        state_serve_thread = std::thread(state_serve_loop);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;
            state_serve_thread.join();
        }
    }

    void state_serve_loop()
    {
        util::mask_signal();

        LOG_INFO << "State server started.";

        std::list<std::pair<std::string, std::string>> state_requests;

        while (!is_shutting_down)
        {
            util::sleep(LOOP_WAIT);

            {
                std::scoped_lock<std::mutex> lock(p2p::ctx.collected_msgs.state_requests_mutex);

                // Move collected state requests over to local requests list.
                if (!p2p::ctx.collected_msgs.state_requests.empty())
                    state_requests.splice(state_requests.end(), p2p::ctx.collected_msgs.state_requests);
            }

            uint64_t time_start = util::get_epoch_milliseconds();

            for (auto &[session_id, request] : state_requests)
            {
                if (is_shutting_down)
                    break;

                const msg::fbuf::p2pmsg::Content *content = msg::fbuf::p2pmsg::GetContent(request.data());

                const p2p::state_request sr = p2pmsg::create_state_request_from_msg(*content->message_as_State_Request_Message());
                flatbuffers::FlatBufferBuilder fbuf(1024);

                uint64_t time_now = util::get_epoch_milliseconds();

                // If we have spent too much time handling state requests, abandon the entire batch
                // because the requester would have stopped waiting for us.
                if ((time_now - time_start) > REQUEST_BATCH_TIMEOUT)
                    break;

                if (state_serve::create_state_response(fbuf, sr) == 0)
                {
                    // Find the peer that we should send the state response to.
                    std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);
                    const auto peer_itr = p2p::ctx.peer_connections.find(session_id);

                    if (peer_itr != p2p::ctx.peer_connections.end())
                    {
                        std::string_view msg = std::string_view(
                            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

                        comm::comm_session *session = peer_itr->second;
                        session->send(msg);
                    }
                }
            }

            state_requests.clear();
        }

        LOG_INFO << "State server stopped.";
    }

    /**
 * Creates the reply message for a given state request.
 * @param fbuf The flatbuffer builder to construct the reply message.
 * @param sr The state request which should be replied to.
 */
    int create_state_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::state_request &sr)
    {
        LOG_DBG << "Serving state req. path:" << sr.parent_path << " block_id:" << sr.block_id;

        // If block_id > -1 this means this is a file block data request.
        if (sr.block_id > -1)
        {
            // Vector to hold the block bytes. Normally block size is constant BLOCK_SIZE (4MB), but the
            // last block of a file may have a smaller size.
            std::vector<uint8_t> block;
            if (get_file_block(block, sr.parent_path, sr.block_id, sr.expected_hash) == -1)
            {
                LOG_ERR << "Error in getting file block: " << sr.parent_path;
                return -1;
            }

            p2p::block_response resp;
            resp.path = sr.parent_path;
            resp.block_id = sr.block_id;
            resp.hash = sr.expected_hash;
            resp.data = std::string_view(reinterpret_cast<const char *>(block.data()), block.size());

            msg::fbuf::p2pmsg::create_msg_from_block_response(fbuf, resp, cons::ctx.lcl);
        }
        else
        {
            // File state request means we have to reply with the file block hash map.
            if (sr.is_file)
            {
                std::vector<hpfs::h32> block_hashes;
                std::size_t file_length = 0;
                if (get_file_block_hashes(block_hashes, file_length, sr.parent_path, sr.expected_hash) == -1)
                {
                    LOG_ERR << "Error in getting block hashes: " << sr.parent_path;
                    return -1;
                }

                msg::fbuf::p2pmsg::create_msg_from_filehashmap_response(
                    fbuf, sr.parent_path, block_hashes,
                    file_length, sr.expected_hash, cons::ctx.lcl);
            }
            else
            {
                // If the state request is for a directory we need to reply with the
                // file system entries and their hashes inside that dir.
                std::vector<hpfs::child_hash_node> child_hash_nodes;
                if (get_fs_entry_hashes(child_hash_nodes, sr.parent_path, sr.expected_hash) == -1)
                {
                    LOG_ERR << "Error in getting fs entries: " << sr.parent_path;
                    return -1;
                }

                msg::fbuf::p2pmsg::create_msg_from_fsentry_response(
                    fbuf, sr.parent_path, child_hash_nodes, sr.expected_hash, cons::ctx.lcl);
            }
        }

        return 0;
    }

    /**
 * Retrieves the specified data block from a state file if expected hash matches.
 * @return Number of bytes read on success. -1 on failure.
 */
    int get_file_block(std::vector<uint8_t> &block, const std::string_view vpath,
                       const uint32_t block_id, const hpfs::h32 expected_hash)
    {
        int fd = 0;
        pid_t hpfs_pid = 0;
        std::string mount_dir;
        if (hpfs::start_fs_session(hpfs_pid, mount_dir, "ro", true) == -1)
            return -1;

        // Check whether the existing block hash matches expected hash.
        std::vector<hpfs::h32> block_hashes;
        if (hpfs::get_file_block_hashes(block_hashes, mount_dir, vpath) == -1)
            goto failure;

        if (block_id >= block_hashes.size())
        {
            LOG_DBG << "Requested block_id " << block_id << " does not exist.";
            goto failure;
        }

        if (block_hashes[block_id] != expected_hash)
        {
            LOG_DBG << "Expected hash mismatch.";
            goto failure;
        }

        // Get actual block data.
        {
            const std::string file_path = std::string(mount_dir).append(vpath);
            const off_t block_offset = block_id * state_common::BLOCK_SIZE;
            fd = open(file_path.c_str(), O_RDONLY);
            if (fd == -1)
            {
                LOG_ERR << errno << ": Open failed. " << file_path;
                goto failure;
            }

            struct stat st;
            if (fstat(fd, &st) == -1)
            {
                LOG_ERR << errno << ": Stat failed. " << file_path;
                goto failure;
            }

            if (!S_ISREG(st.st_mode))
            {
                LOG_ERR << "Not a file. " << file_path;
                goto failure;
            }

            if (block_offset > st.st_size)
            {
                LOG_ERR << "Block offset " << block_offset << " larger than file " << st.st_size << " - " << file_path;
                goto failure;
            }

            const size_t read_len = MIN(state_common::BLOCK_SIZE, (st.st_size - block_offset));
            block.resize(read_len);

            lseek(fd, block_offset, SEEK_SET);
            const int res = read(fd, block.data(), read_len);
            if (res < read_len)
            {
                LOG_ERR << errno << ": Read failed (result:" << res
                        << " off:" << block_offset << " len:" << read_len << "). " << file_path;
                goto failure;
            }
        }

        goto success;

    failure:
        if (fd > 0)
            close(fd);
        util::kill_process(hpfs_pid, true);
        return -1;
    success:
        if (fd > 0)
            close(fd);
        if (util::kill_process(hpfs_pid, true) == -1)
            return -1;
        return 0;
    }

    int get_file_block_hashes(std::vector<hpfs::h32> &hashes, size_t &file_length,
                              const std::string_view vpath, const hpfs::h32 expected_hash)
    {
        pid_t hpfs_pid = 0;
        std::string mount_dir;
        if (hpfs::start_fs_session(hpfs_pid, mount_dir, "ro", true) == -1)
            return -1;

        // Check whether the existing file hash matches expected hash.
        hpfs::h32 file_hash = hpfs::h32_empty;
        if (hpfs::get_hash(file_hash, mount_dir, vpath) == -1)
            goto failure;

        if (file_hash != expected_hash)
        {
            LOG_DBG << "Expected hash mismatch.";
            goto failure;
        }

        // Get the block hashes.
        if (hpfs::get_file_block_hashes(hashes, mount_dir, vpath) == -1)
            goto failure;

        // Get actual file length.
        {
            const std::string file_path = std::string(mount_dir).append(vpath);
            struct stat st;
            if (stat(file_path.c_str(), &st) == -1)
            {
                LOG_ERR << errno << ": Stat failed. " << file_path;
                goto failure;
            }
            file_length = st.st_size;
        }

        goto success;

    failure:
        util::kill_process(hpfs_pid, true);
        return -1;
    success:
        if (util::kill_process(hpfs_pid, true) == -1)
            return -1;
        return 0;
    }

    int get_fs_entry_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                            const std::string_view vpath, const hpfs::h32 expected_hash)
    {
        pid_t hpfs_pid = 0;
        std::string mount_dir;
        if (hpfs::start_fs_session(hpfs_pid, mount_dir, "ro", true) == -1)
            return -1;

        // Check whether the existing dir hash matches expected hash.
        hpfs::h32 dir_hash = hpfs::h32_empty;
        if (hpfs::get_hash(dir_hash, mount_dir, vpath) == -1)
            goto failure;

        if (dir_hash != expected_hash)
        {
            LOG_DBG << "Expected hash mismatch.";
            goto failure;
        }

        // Get the children hash nodes.
        if (hpfs::get_dir_children_hashes(hash_nodes, mount_dir, vpath) == -1)
            goto failure;

        goto success;

    failure:
        util::kill_process(hpfs_pid, true);
        return -1;
    success:
        if (util::kill_process(hpfs_pid, true) == -1)
            return -1;
        return 0;
    }
} // namespace state_serve