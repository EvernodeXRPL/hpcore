#ifndef _HP_CONS_STATE_SYNC_HPFS_
#define _HP_CONS_STATE_SYNC_HPFS_

#include "../hpfs/h32.hpp"
#include "../hpfs/hpfs.hpp"

namespace state_sync
{
    int get_file_block(std::vector<uint8_t> &vec, const std::string_view vpath,
                       const uint32_t block_id, const hpfs::h32 expected_hash);

    int get_file_block_hashes(std::vector<hpfs::h32> &hashes, size_t &file_length,
                              const std::string_view vpath, const hpfs::h32 expected_hash);

    int get_dir_children_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                                const std::string_view vpath, const hpfs::h32 expected_hash);
} // namespace state_sync

#endif