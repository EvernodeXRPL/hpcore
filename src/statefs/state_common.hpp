#ifndef _STATEFS_STATE_COMMON_
#define _STATEFS_STATE_COMMON_

#include <sys/types.h>
#include <string>
#include "hasher.hpp"

namespace statefs
{

// Cache block size.
constexpr size_t BLOCK_SIZE = 4 * 1024; //* 1024; // 4MB

// Cache block index entry bytes length.
constexpr size_t BLOCKINDEX_ENTRY_SIZE = 44;
constexpr size_t MAX_HASHES = BLOCK_SIZE / hasher::HASH_SIZE;

// Permissions used when creating block cache and index files.
constexpr int FILE_PERMS = 0644;

const char *const HASHMAP_EXT = ".bhmap";
constexpr size_t HASHMAP_EXT_LEN = 6;

const char *const BLOCKINDEX_EXT = ".bindex";
constexpr size_t BLOCKINDEX_EXT_LEN = 7;

const char *const BLOCKCACHE_EXT = ".bcache";
constexpr size_t BLOCKCACHE_EXT_LEN = 7;

const char *const IDX_NEWFILES = "/idxnew.idx";
const char *const IDX_TOUCHEDFILES = "/idxtouched.idx";
const char *const DIRHASH_FNAME = "dir.hash";

const char *const DATA_DIR = "/data";
const char *const BHMAP_DIR = "/bhmap";
const char *const HTREE_DIR = "/htree";
const char *const DELTA_DIR = "/delta";

constexpr int16_t MAX_CHECKPOINTS = 5;

extern std::string statehistdir;

struct statedir_context
{
    std::string rootdir;
    std::string datadir;
    std::string blockhashmapdir;
    std::string hashtreedir;
    std::string deltadir;
};

statedir_context init(const std::string &statehist_dir_root);
std::string get_statedir_root(const int16_t checkpointid);
statedir_context get_statedir_context(int16_t checkpointid = 0, bool createdirs = false);
std::string get_relpath(const std::string &fullpath, const std::string &base_path);
std::string switch_basepath(const std::string &fullpath, const std::string &from_base_path, const std::string &to_base_path);

} // namespace statefs

#endif