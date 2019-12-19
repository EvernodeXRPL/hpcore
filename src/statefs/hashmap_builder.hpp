#ifndef _HP_STATEFS_HASHMAP_BUILDER_
#define _HP_STATEFS_HASHMAP_BUILDER_

#include "../pchheader.hpp"
#include "hasher.hpp"
#include "state_common.hpp"

namespace statefs
{

class hashmap_builder
{
private:
    const state_dir_context ctx;
    // List of new block hash map sub directories created during the session.
    std::unordered_set<std::string> created_bhmapsubdirs;

    int read_block_hashmap(std::vector<char> &bhmap_data, std::string &hmapfile, const std::string &relpath);
    int get_delta_block_index(std::map<uint32_t, hasher::B2H> &idxmap, uint32_t &total_block_count, const std::string &file_relpath);
    int update_hashes_with_backup_block_hints(
        hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
        const uint32_t block_count, const uint32_t original_block_count, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmap_data);
    int update_hashes_with_changed_block_hints(
        hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
        const uint32_t block_count, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmap_data);
    int compute_blockhash(hasher::B2H &hash, const uint32_t block_id, const int filefd, const std::string &relpath);
    int write_block_hashmap(const std::string &bhmap_file, const hasher::B2H *hashes, const off_t hashes_size);
    int update_hashtree_entry(hasher::B2H &parent_dir_hash, const bool old_bhmap_exists, const hasher::B2H old_file_hash, const hasher::B2H new_file_hash, const std::string &bhmap_file, const std::string &relpath);

public:
    hashmap_builder(const state_dir_context &ctx);
    int generate_hashmap_forfile(hasher::B2H &parent_dir_hash, const std::string &filepath, const std::string &file_relpath, const std::map<uint32_t, hasher::B2H> &changed_blocks);
    int remove_hashmapfile(hasher::B2H &parent_dir_hash, const std::string &filepath);
};

} // namespace statefs

#endif
