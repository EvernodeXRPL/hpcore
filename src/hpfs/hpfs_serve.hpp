#ifndef _HP_HPFS_HPFS_SERVE_
#define _HP_HPFS_HPFS_SERVE_

#include "../util/h32.hpp"
#include "hpfs_mount.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"

namespace hpfs
{
    class hpfs_serve
    {
    private:
        bool is_shutting_down = false;
        bool init_success = false;
        std::thread hpfs_serve_thread;
        hpfs::hpfs_mount *fs_mount = NULL;
        std::string_view name;
        void hpfs_serve_loop();

    protected:
        std::list<std::pair<std::string, p2p::hpfs_request>> hpfs_requests;
        // Move the collected requests from hpfs requests to a local response list.
        virtual void swap_collected_requests() = 0; // Must override in child classes.

    public:
        int init(std::string_view server_name, hpfs::hpfs_mount *fs_mount_ptr);

        void deinit();

        int create_hpfs_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::hpfs_request &hr, std::string_view lcl, const p2p::sequence_hash &last_primary_shard_id);

        int get_data_block(std::vector<uint8_t> &block, const std::string_view vpath,
                           const uint32_t block_id, const util::h32 expected_hash);

        int get_data_block_hashes(std::vector<util::h32> &hashes, size_t &file_length,
                                  const std::string_view vpath, const util::h32 expected_hash);

        int get_fs_entry_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                                const std::string_view vpath, const util::h32 expected_hash);
    };
} // namespace hpfs

#endif