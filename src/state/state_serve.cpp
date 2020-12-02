#include "../pchheader.hpp"
#include "../hpfs/hpfs.hpp"
#include "../hpfs/h32.hpp"
#include "../util/util.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../ledger.hpp"
#include "../hplog.hpp"
#include "state_serve.hpp"
#include "state_common.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

/**
 * Helper functions for serving state requests from other peers.
 */
namespace state_serve
{
    constexpr uint16_t LOOP_WAIT = 20; // Milliseconds

    uint16_t REQUEST_BATCH_TIMEOUT;

    bool is_shutting_down = false;
    bool init_success = false;
    pid_t hpfs_pid;
    std::thread state_serve_thread;

    int init()
    {
        REQUEST_BATCH_TIMEOUT = state_common::get_request_resubmit_timeout() * 0.9;

        if (hpfs::start_ro_rw_process(hpfs_pid, conf::ctx.state_serve_dir, true, true, false) == -1)
            return -1;

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

            LOG_DEBUG << "Stopping hpfs state serve process... pid:" << hpfs_pid;
            if (hpfs_pid > 0 && util::kill_process(hpfs_pid, true) == 0)
                LOG_INFO << "Stopped hpfs state serve process.";
        }
    }

    void state_serve_loop()
    {
        util::mask_signal();

        LOG_INFO << "State server started.";

        std::list<std::pair<std::string, std::string>> state_requests;

        // Indicates whether any requests were processed in the previous loop iteration.
        bool prev_requests_processed = false;

        while (!is_shutting_down)
        {
            // Wait a small delay if there were no requests processed during previous iteration.
            if (!prev_requests_processed)
                util::sleep(LOOP_WAIT);

            {
                std::scoped_lock<std::mutex> lock(p2p::ctx.collected_msgs.state_requests_mutex);

                // Move collected state requests over to local requests list.
                if (!p2p::ctx.collected_msgs.state_requests.empty())
                    state_requests.splice(state_requests.end(), p2p::ctx.collected_msgs.state_requests);
            }

            prev_requests_processed = !state_requests.empty();
            const uint64_t time_start = util::get_epoch_milliseconds();
            const std::string lcl = ledger::ctx.get_lcl();

            if (state_requests.empty())
                continue;

            if (hpfs::start_fs_session(conf::ctx.state_serve_dir) != -1)
            {
                for (auto &[session_id, request] : state_requests)
                {
                    if (is_shutting_down)
                        break;

                    // If we have spent too much time handling state requests, abandon the entire batch
                    // because the requester would have stopped waiting for us.
                    const uint64_t time_now = util::get_epoch_milliseconds();
                    if ((time_now - time_start) > REQUEST_BATCH_TIMEOUT)
                    {
                        LOG_DEBUG << "State serve batch timeout. Abandonding state requests.";
                        break;
                    }

                    // Session id is in binary format. Converting to hex before printing.
                    std::string session_id_hex;
                    util::bin2hex(
                        session_id_hex,
                        reinterpret_cast<const unsigned char *>(session_id.data()),
                        session_id.length());

                    LOG_DEBUG << "Serving state request from [" << session_id_hex.substr(0, 10) << "]";

                    const msg::fbuf::p2pmsg::Content *content = msg::fbuf::p2pmsg::GetContent(request.data());

                    const p2p::state_request sr = p2pmsg::create_state_request_from_msg(*content->message_as_State_Request_Message());
                    flatbuffers::FlatBufferBuilder fbuf(1024);

                    if (state_serve::create_state_response(fbuf, sr, lcl) == 1)
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

                hpfs::stop_fs_session(conf::ctx.state_serve_dir);
            }

            state_requests.clear();
        }

        LOG_INFO << "State server stopped.";
    }

    /**
     * Creates the reply message for a given state request.
     * @param fbuf The flatbuffer builder to construct the reply message.
     * @param sr The state request which should be replied to.
     * @return 1 if successful state response was generated. 0 if request is invalid
     *         and no response was generated. -1 on error.
     */
    int create_state_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::state_request &sr, std::string_view lcl)
    {
        LOG_DEBUG << "Serving state req. path:" << sr.parent_path << " block_id:" << sr.block_id;

        // If block_id > -1 this means this is a file block data request.
        if (sr.block_id > -1)
        {
            // Vector to hold the block bytes. Normally block size is constant BLOCK_SIZE (4MB), but the
            // last block of a file may have a smaller size.
            std::vector<uint8_t> block;
            const int result = get_data_block(block, sr.parent_path, sr.block_id, sr.expected_hash);

            if (result == -1)
            {
                LOG_ERROR << "Error in getting file block: " << sr.parent_path;
                return -1;
            }
            else if (result == 1)
            {
                p2p::block_response resp;
                resp.path = sr.parent_path;
                resp.block_id = sr.block_id;
                resp.hash = sr.expected_hash;
                resp.data = std::string_view(reinterpret_cast<const char *>(block.data()), block.size());

                msg::fbuf::p2pmsg::create_msg_from_block_response(fbuf, resp, lcl);
                return 1; // Success.
            }
        }
        else
        {
            // File state request means we have to reply with the file block hash map.
            if (sr.is_file)
            {
                std::vector<hpfs::h32> block_hashes;
                std::size_t file_length = 0;
                const int result = get_data_block_hashes(block_hashes, file_length, sr.parent_path, sr.expected_hash);

                if (result == -1)
                {
                    LOG_ERROR << "Error in getting block hashes: " << sr.parent_path;
                    return -1;
                }
                else if (result == 1)
                {
                    msg::fbuf::p2pmsg::create_msg_from_filehashmap_response(
                        fbuf, sr.parent_path, block_hashes,
                        file_length, sr.expected_hash, lcl);
                    return 1; // Success.
                }
            }
            else
            {
                // If the state request is for a directory we need to reply with the
                // file system entries and their hashes inside that dir.
                std::vector<hpfs::child_hash_node> child_hash_nodes;
                const int result = get_fs_entry_hashes(child_hash_nodes, sr.parent_path, sr.expected_hash);

                if (result == -1)
                {
                    LOG_ERROR << "Error in getting fs entries: " << sr.parent_path;
                    return -1;
                }
                else if (result == 1)
                {
                    msg::fbuf::p2pmsg::create_msg_from_fsentry_response(
                        fbuf, sr.parent_path, child_hash_nodes, sr.expected_hash, lcl);
                    return 1; // Success.
                }
            }
        }

        LOG_DEBUG << "No state response generated.";
        return 0;
    }

    /**
     * Retrieves the specified data block from a state file if expected hash matches.
     * @return 1 if block data was succefully fetched. 0 if vpath or block does not exist. -1 on error.
     */
    int get_data_block(std::vector<uint8_t> &block, const std::string_view vpath,
                       const uint32_t block_id, const hpfs::h32 expected_hash)
    {
        // Check whether the existing block hash matches expected hash.
        std::vector<hpfs::h32> block_hashes;
        int result = hpfs::get_file_block_hashes(block_hashes, conf::ctx.state_serve_dir, vpath);
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
                struct stat st;
                const std::string file_path = std::string(conf::ctx.state_serve_dir).append(vpath);
                const off_t block_offset = block_id * state_common::BLOCK_SIZE;
                const int fd = open(file_path.c_str(), O_RDONLY | O_CLOEXEC);
                if (fd == -1)
                {
                    LOG_ERROR << errno << ": Open failed. " << file_path;
                    result = -1;
                }
                else
                {
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
                        const size_t read_len = MIN(state_common::BLOCK_SIZE, (st.st_size - block_offset));
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
                            result = 1; // Success.
                        }
                    }

                    close(fd);
                }
            }
        }

        return result;
    }

    /**
     * Retrieves the specified file block hashes if expected hash matches.
     * @return 1 if block hashes were successfuly fetched. 0 if vpath does not exist. -1 on error.
     */
    int get_data_block_hashes(std::vector<hpfs::h32> &hashes, size_t &file_length,
                              const std::string_view vpath, const hpfs::h32 expected_hash)
    {
        // Check whether the existing file hash matches expected hash.
        hpfs::h32 file_hash = hpfs::h32_empty;
        int result = hpfs::get_hash(file_hash, conf::ctx.state_serve_dir, vpath);
        if (result == 1)
        {
            if (file_hash != expected_hash)
            {
                LOG_DEBUG << "Expected hash mismatch.";
                result = 0;
            }
            // Get the block hashes.
            else if (hpfs::get_file_block_hashes(hashes, conf::ctx.state_serve_dir, vpath) < 0)
            {
                result = -1;
            }
            else
            {
                // Get actual file length.
                const std::string file_path = std::string(conf::ctx.state_serve_dir).append(vpath);
                struct stat st;
                if (stat(file_path.c_str(), &st) == -1)
                {
                    LOG_ERROR << errno << ": Stat failed when getting file length. " << file_path;
                    result = -1;
                }
                file_length = st.st_size;
                result = 1; // Success.
            }
        }

        return result;
    }

    /**
     * Retrieves the specified dir entry hashes if expected fir hash matches.
     * @return 1 if fs entry hashes were successfuly fetched. 0 if vpath does not exist. -1 on error.
     */
    int get_fs_entry_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                            const std::string_view vpath, const hpfs::h32 expected_hash)
    {
        // Check whether the existing dir hash matches expected hash.
        hpfs::h32 dir_hash = hpfs::h32_empty;
        int result = hpfs::get_hash(dir_hash, conf::ctx.state_serve_dir, vpath);
        if (result == 1)
        {
            if (dir_hash != expected_hash)
            {
                LOG_DEBUG << "Expected hash mismatch.";
                result = 0;
            }
            // Get the children hash nodes.
            else if (hpfs::get_dir_children_hashes(hash_nodes, conf::ctx.state_serve_dir, vpath) < 0)
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
} // namespace state_serve