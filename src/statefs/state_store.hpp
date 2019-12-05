#ifndef _HP_STATEFS_STATE_STORE_
#define _HP_STATEFS_STATE_STORE_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "hasher.hpp"

namespace statefs
{

// Map of modified/deleted files with updated blockids and hashes (if modified).
extern std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touchedfiles;

bool is_dir_exists(const std::string &dirrelpath);
int get_fsentry_hashes(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries, const std::string &dirrelpath);
int get_blockhashmap(std::vector<uint8_t> &vec, const std::string &filerelpath);
int get_filelength(const std::string &filerelpath);
int get_block(std::vector<uint8_t> &vec, const std::string &filerelpath, const uint32_t blockid);
void create_dir(const std::string &dirrelpath);
int delete_dir(const std::string &dirrelpath);
int delete_file(const std::string &filerelpath);
int truncate_file(const std::string &filerelpath, const size_t newsize);
int write_block(const std::string &filerelpath, const uint32_t blockid, const void *buf, const size_t len);
int compute_hashtree(hasher::B2H &statehash, const bool force_all = false);

/**
 * Private helper functions.
 */

int read_file_bytes(void *buf, const char *filepath, const off_t start, const size_t len);
int read_file_bytes_toend(std::vector<uint8_t> &vec, const char *filepath, const off_t start);

} // namespace statefs

#endif