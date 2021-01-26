#ifndef _HP_HPFS_HPFS_SERVE_
#define _HP_HPFS_HPFS_SERVE_

#include "../util/h32.hpp"
#include "hpfs_mount.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"

namespace hpfs_serve
{
    int init();

    void deinit();
    
    void hpfs_serve_loop();

    int create_hpfs_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::hpfs_request &sr, std::string_view lcl);

    int get_data_block(std::vector<uint8_t> &vec, const std::string_view vpath,
                       const uint32_t block_id, const util::h32 expected_hash);

    int get_data_block_hashes(std::vector<util::h32> &hashes, size_t &file_length,
                              const std::string_view vpath, const util::h32 expected_hash);

    int get_fs_entry_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                                const std::string_view vpath, const util::h32 expected_hash);
} // namespace hpfs_sync

#endif