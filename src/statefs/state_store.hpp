#ifndef _HP_STATEFS_STATE_STORE_
#define _HP_STATEFS_STATE_STORE_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "hasher.hpp"

namespace statefs
{

int get_fsentry_hashes(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries, const std::string &dirrelpath);
int get_block_hashes(std::vector<uint8_t> &vec, const std::string &filerelpath);

std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touchedfiles;

//int get_fsentry_hashes(std::vector<fs_hash_entry> &hashlist, const std::string &dirrelpath);
int get_blockhashmap(std::vector<uint8_t> &vec, const std::string &filerelpath);
int get_block(const std::string &filerelpath, const uint32_t blockid);
int delete_folder(const std::string &dirrelpath);
int delete_file(const std::string &filerelpath);
int truncate_file(const std::string &filerelpath, const size_t newsize);
int write_block(const std::string &filerelpath, const uint32_t blockid, const void *buf, const size_t len);
int compute_hashtree();

/**
 * Private helper functions.
 */

int read_file_bytes(void *buf, const char *bhmapfile, const off_t start, const size_t len);
int read_file_bytes_toend(std::vector<uint8_t> &vec, const char *bhmapfile, const off_t start);

} // namespace statefs

#endif