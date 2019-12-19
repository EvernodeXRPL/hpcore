#ifndef _HP_STATEFS_STATE_COMMON_
#define _HP_STATEFS_STATE_COMMON_

#include <sys/types.h>
#include <string>
#include "hasher.hpp"

namespace statefs
{

// Max number of state history checkpoints to keep.
constexpr int16_t MAX_CHECKPOINTS = 5;

// Cache block size.
constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB

// Cache block index entry bytes length.
constexpr size_t BLOCK_INDEX_ENTRY_SIZE = 44;

// Permissions used when creating block cache and index files.
constexpr int FILE_PERMS = 0644;

const char *const BLOCK_HASHMAP_EXT = ".bhmap";
constexpr size_t BLOCK_HASHMAP_EXT_LEN = 6;

const char *const BLOCK_INDEX_EXT = ".bindex";
constexpr size_t BLOCK_INDEX_EXT_LEN = 7;

const char *const BLOCK_CACHE_EXT = ".bcache";
constexpr size_t BLOCK_CACHE_EXT_LEN = 7;

const char *const IDX_NEW_FILES = "/idxnew.idx";
const char *const IDX_TOUCHED_FILES = "/idxtouched.idx";
const char *const DIR_HASH_FNAME = "dir.hash";

const char *const DATA_DIR = "/data";
const char *const BHMAP_DIR = "/bhmap";
const char *const HTREE_DIR = "/htree";
const char *const DELTA_DIR = "/delta";

/**
 * Context struct to hold all state-related directory paths.
 */
struct state_dir_context
{
    std::string root_dir;            // Directory holding state sub dirs.
    std::string data_dir;            // Directory containing smart contract data.
    std::string block_hashmap_dir;    // Directory containing block hash map files.
    std::string hashtree_dir;        // Directory containing hash tree files (dir.hash and hard links).
    std::string delta_dir;           // Directory containing original smart contract data.
};

// Container directory to contain all checkpoints.
extern std::string state_hist_dir;

// Currently loaded state checkpoint directory context (usually checkpoint 0)
extern state_dir_context current_ctx;

void init(const std::string &state_hist_dir_root);
std::string get_state_dir_root(const int16_t checkpoint_id);
state_dir_context get_state_dir_context(int16_t checkpoint_id = 0, bool create_dirs = false);
std::string get_relpath(const std::string &fullpath, const std::string &base_path);
std::string switch_basepath(const std::string &fullpath, const std::string &from_base_path, const std::string &to_base_path);

} // namespace statefs

#endif