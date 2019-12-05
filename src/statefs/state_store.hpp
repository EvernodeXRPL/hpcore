#ifndef _HP_STATEFS_STATE_STORE_
#define _HP_STATEFS_STATE_STORE_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "hasher.hpp"

namespace statefs
{

// Map of modified/deleted files with updated blockids and hashes (if modified).
extern std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touched_files;

bool is_dir_exists(const std::string &dir_relpath);
int get_fs_entry_hashes(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries, const std::string &dir_relpath);
int get_block_hash_map(std::vector<uint8_t> &vec, const std::string &file_relpath);
int get_file_length(const std::string &file_relpath);
int get_block(std::vector<uint8_t> &vec, const std::string &file_relpath, const uint32_t block_id);
void create_dir(const std::string &dir_relpath);
int delete_dir(const std::string &dir_relpath);
int delete_file(const std::string &file_relpath);
int truncate_file(const std::string &file_relpath, const size_t newsize);
int write_block(const std::string &file_relpath, const uint32_t block_id, const void *buf, const size_t len);
int compute_hash_tree(hasher::B2H &statehash, const bool force_all = false);

/**
 * Private helper functions.
 */

int read_file_bytes(void *buf, const char *filepath, const off_t start, const size_t len);
int read_file_bytes_to_end(std::vector<uint8_t> &vec, const char *filepath, const off_t start);

} // namespace statefs

#endif