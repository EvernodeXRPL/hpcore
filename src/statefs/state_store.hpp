#ifndef _HP_STATEFS_STATE_STORE_
#define _HP_STATEFS_STATE_STORE_

#include "../pchheader.hpp"

namespace statefs
{

//int get_fsentry_hashes(std::vector<fs_hash_entry> &hashlist, const std::string &dirrelpath);
int get_block_hashes(std::vector<uint8_t> &vec, const std::string &filerelpath);
int delete_folder(const std::string &dirrelpath);
int delete_file(const std::string &filerelpath);
int truncate_file(const std::string &filerelpath, const size_t newsize);
int write_block(const std::string &filerelpath, const uint32_t blockid, const void *buf, const size_t len);

/**
 * Private helper functions.
 */

int read_file_bytes(void *buf, const char *bhmapfile, const off_t start, const size_t len);
int read_file_bytes(std::vector<uint8_t> &vec, const char *bhmapfile, const off_t start);

} // namespace statefs

#endif