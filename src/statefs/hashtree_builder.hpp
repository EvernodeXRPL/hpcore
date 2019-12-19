#ifndef _HP_STATEFS_HASHTREE_BUILDER_
#define _HP_STATEFS_HASHTREE_BUILDER_

#include "../pchheader.hpp"
#include "hasher.hpp"
#include "hashmap_builder.hpp"
#include "state_common.hpp"

namespace statefs
{

typedef std::unordered_map<std::string, std::unordered_set<std::string>> hintpath_map;

class hashtree_builder
{
private:
    const state_dir_context ctx;
    hashmap_builder hmapbuilder;

    // Hint path map with parent dir as key and list of file paths under each parent dir.
    hintpath_map hint_paths;
    bool force_rebuild_all;
    bool hint_mode;
    bool removal_mode;
    std::string traversel_rootdir;
    std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> file_block_index;

    // List of new root hash map sub directories created during the session.
    std::unordered_set<std::string> created_htree_subdirs;

    int traverse_and_generate(hasher::B2H &root_hash);
    int update_hashtree(hasher::B2H &root_hash);
    int update_hashtree_fordir(hasher::B2H &parent_dir_hash, const std::string &relpath, const hintpath_map::iterator hint_dir_itr, const bool is_root_level);

    hasher::B2H get_existing_dir_hash(const std::string &dir_hash_file);
    int save_dir_hash(const std::string &dir_hash_file, hasher::B2H dir_hash);
    bool should_process_dir(hintpath_map::iterator &hint_subdir_itr, const std::string &dirpath);
    bool should_process_file(const hintpath_map::iterator hint_dir_itr, const std::string filepath);
    int process_file(hasher::B2H &parent_dir_hash, const std::string &filepath, const std::string &htree_dirpath);
    int update_hashtree_entry(hasher::B2H &parent_dir_hash, const bool old_bhmap_exists, const hasher::B2H old_file_hash, const hasher::B2H new_file_hash, const std::string &bhmap_file, const std::string &relpath);
    void populate_hint_paths_from_idx_file(const char *const idxfile);
    void insert_hint_path(const std::string &relpath);
    bool get_hinteddir_match(hintpath_map::iterator &match_itr, const std::string &dirpath);

public:
    hashtree_builder(const state_dir_context &ctx);
    int generate(hasher::B2H &root_hash);
    int generate(hasher::B2H &root_hash, const bool force_all);
    int generate(hasher::B2H &root_hash, const std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> &touched_files);
};

} // namespace statefs

#endif
