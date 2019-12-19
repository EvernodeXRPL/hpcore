#include "../pchheader.hpp"
#include "hashtree_builder.hpp"
#include "state_restore.hpp"
#include "state_common.hpp"

namespace statefs
{

hashtree_builder::hashtree_builder(const state_dir_context &ctx) : ctx(ctx), hmapbuilder(ctx)
{
    force_rebuild_all = false;
    hint_mode = false;
}

int hashtree_builder::generate(hasher::B2H &root_hash)
{
    // Load modified file path hints if available.
    populate_hint_paths_from_idx_file(IDX_TOUCHED_FILES);
    populate_hint_paths_from_idx_file(IDX_NEW_FILES);
    hint_mode = !hint_paths.empty();

    return traverse_and_generate(root_hash);
}

int hashtree_builder::generate(hasher::B2H &root_hash, const bool force_all)
{
    force_rebuild_all = force_all;
    if (force_rebuild_all)
    {
        boost::filesystem::remove_all(ctx.block_hashmap_dir);
        boost::filesystem::remove_all(ctx.hashtree_dir);

        boost::filesystem::create_directories(ctx.block_hashmap_dir);
        boost::filesystem::create_directories(ctx.hashtree_dir);
    }

    return traverse_and_generate(root_hash);
}

int hashtree_builder::generate(hasher::B2H &root_hash, const std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> &touched_files)
{
    hint_mode = true;
    file_block_index = touched_files;
    for (const auto &[relpath, bindex] : touched_files)
        insert_hint_path(relpath);

    return traverse_and_generate(root_hash);
}

int hashtree_builder::traverse_and_generate(hasher::B2H &root_hash)
{
    // Load current root hash if exist.
    const std::string dir_hash_file = ctx.hashtree_dir + "/" + DIR_HASH_FNAME;
    root_hash = get_existing_dir_hash(dir_hash_file);

    traversel_rootdir = ctx.data_dir;
    removal_mode = false;
    if (update_hashtree(root_hash) != 0)
        return -1;

    // If there are any remaining hint files directly under this directory, that means
    // those files are no longer there. So we need to delete the corresponding .bhmap and rh files
    // and adjust the directory hash accordingly.
    if (hint_mode && !hint_paths.empty())
    {
        traversel_rootdir = ctx.block_hashmap_dir;
        removal_mode = true;
        if (update_hashtree(root_hash) != 0)
            return -1;
    }

    return 0;
}

int hashtree_builder::update_hashtree(hasher::B2H &root_hash)
{
    hintpath_map::iterator hint_dir_itr = hint_paths.end();
    if (!should_process_dir(hint_dir_itr, traversel_rootdir))
        return 0;

    if (update_hashtree_fordir(root_hash, traversel_rootdir, hint_dir_itr, true) != 0)
        return -1;

    return 0;
}

int hashtree_builder::update_hashtree_fordir(hasher::B2H &parent_dir_hash, const std::string &dirpath, const hintpath_map::iterator hint_dir_itr, const bool is_root_level)
{
    const std::string htree_dirpath = switch_base_path(dirpath, traversel_rootdir, ctx.hashtree_dir);

    // Load current dir hash if exist.
    const std::string dir_hash_file = htree_dirpath + "/" + DIR_HASH_FNAME;
    hasher::B2H dir_hash = get_existing_dir_hash(dir_hash_file);

    // Remember the dir hash before we mutate it.
    hasher::B2H original_dir_hash = dir_hash;

    // Iterate files/subdirs inside this dir.
    const boost::filesystem::directory_iterator itr_end;
    for (boost::filesystem::directory_iterator itr(dirpath); itr != itr_end; itr++)
    {
        const bool is_dir = boost::filesystem::is_directory(itr->path());
        const std::string path_str = itr->path().string();

        if (is_dir)
        {
            hintpath_map::iterator hint_subdir_itr = hint_paths.end();
            if (!should_process_dir(hint_subdir_itr, path_str))
                continue;

            if (update_hashtree_fordir(dir_hash, path_str, hint_subdir_itr, false) != 0)
                return -1;
        }
        else
        {
            if (!should_process_file(hint_dir_itr, path_str))
                continue;

            if (process_file(dir_hash, path_str, htree_dirpath) != 0)
                return -1;
        }
    }

    // If there are no more files in the hint dir, delete the hint dir entry as well.
    if (hint_dir_itr != hint_paths.end() && hint_dir_itr->second.empty())
        hint_paths.erase(hint_dir_itr);

    // In removalmode, we check whether the dir is empty. If so we remove the dir as well.
    if (removal_mode && boost::filesystem::is_empty(dirpath))
    {
        // We remove the dirs if we are below root level only.
        // Otherwise we only remove root dir.hash file.
        if (!is_root_level)
        {
            boost::filesystem::remove_all(dirpath);
            boost::filesystem::remove_all(htree_dirpath);
        }
        else
        {
            boost::filesystem::remove(dir_hash_file);
        }

        // Subtract the original dir hash from the parent dir hash.
        parent_dir_hash ^= original_dir_hash;
    }
    else if (dir_hash != original_dir_hash)
    {
        // If dir hash has changed, write it back to dir hash file.
        if (save_dir_hash(dir_hash_file, dir_hash) == -1)
            return -1;

        // Also update the parent dir hash by subtracting the old hash and adding the new hash.
        parent_dir_hash ^= original_dir_hash;
        parent_dir_hash ^= dir_hash;
    }
    else
    {
        parent_dir_hash = dir_hash;
    }

    return 0;
}

hasher::B2H hashtree_builder::get_existing_dir_hash(const std::string &dir_hash_file)
{
    // Load current dir hash if exist.
    hasher::B2H dir_hash = hasher::B2H_empty;
    int dir_hash_fd = open(dir_hash_file.c_str(), O_RDONLY);
    if (dir_hash_fd > 0)
    {
        read(dir_hash_fd, &dir_hash, hasher::HASH_SIZE);
        close(dir_hash_fd);
    }
    return dir_hash;
}

int hashtree_builder::save_dir_hash(const std::string &dir_hash_file, hasher::B2H dir_hash)
{
    int dir_hash_fd = open(dir_hash_file.c_str(), O_RDWR | O_TRUNC | O_CREAT, FILE_PERMS);
    if (dir_hash_fd == -1)
        return -1;

    if (write(dir_hash_fd, &dir_hash, hasher::HASH_SIZE) == -1)
    {
        close(dir_hash_fd);
        return -1;
    }

    close(dir_hash_fd);
    return 0;
}

inline bool hashtree_builder::should_process_dir(hintpath_map::iterator &dir_itr, const std::string &dirpath)
{
    if (force_rebuild_all)
        return true;

    return (hint_mode ? get_hinteddir_match(dir_itr, dirpath) : true);
}

bool hashtree_builder::should_process_file(const hintpath_map::iterator hint_dir_itr, const std::string filepath)
{
    if (force_rebuild_all)
        return true;

    if (hint_mode)
    {
        if (hint_dir_itr == hint_paths.end())
            return false;

        std::string relpath = get_relpath(filepath, traversel_rootdir);

        // If in removal mode, we are traversing .bhmap files. Hence we should truncate .bhmap extension
        // before we search for the path in file hints.
        if (removal_mode)
            relpath = relpath.substr(0, relpath.length() - BLOCK_HASHMAP_EXT_LEN);

        std::unordered_set<std::string> &hint_files = hint_dir_itr->second;
        const auto hint_file_itr = hint_files.find(relpath);
        if (hint_file_itr == hint_files.end())
            return false;

        // Erase the visiting filepath from hint files.
        hint_files.erase(hint_file_itr);
    }
    return true;
}

int hashtree_builder::process_file(hasher::B2H &parent_dir_hash, const std::string &filepath, const std::string &htree_dirpath)
{
    if (!removal_mode)
    {
        // Create directory tree if not exist so we are able to create the file root hash files (hard links).
        if (created_htree_subdirs.count(htree_dirpath) == 0)
        {
            boost::filesystem::create_directories(htree_dirpath);
            created_htree_subdirs.emplace(htree_dirpath);
        }

        const std::string relpath = get_relpath(filepath, ctx.data_dir);
        const std::map<uint32_t, hasher::B2H> &changed_blocks = file_block_index[relpath];

        if (hmapbuilder.generate_hashmap_for_file(parent_dir_hash, filepath, relpath, changed_blocks) == -1)
            return -1;
    }
    else
    {
        if (hmapbuilder.remove_hashmap_file(parent_dir_hash, filepath) == -1)
            return -1;
    }

    return 0;
}

void hashtree_builder::populate_hint_paths_from_idx_file(const char *const idxfile)
{
    std::ifstream in_file(std::string(ctx.delta_dir).append(idxfile));
    if (!in_file.fail())
    {
        for (std::string relpath; std::getline(in_file, relpath);)
            insert_hint_path(relpath);
        in_file.close();
    }
}

void hashtree_builder::insert_hint_path(const std::string &relpath)
{
    boost::filesystem::path p_relpath(relpath);
    std::string parent_dir = p_relpath.parent_path().string();
    hint_paths[parent_dir].emplace(relpath);
}

bool hashtree_builder::get_hinteddir_match(hintpath_map::iterator &match_itr, const std::string &dirpath)
{
    // First check whether there's an exact match. If not check for a partial match.
    // Exact match will return the iterator. Partial match or not found will return end() iterator.
    const std::string relpath = get_relpath(dirpath, traversel_rootdir);
    const auto exact_match_itr = hint_paths.find(relpath);

    if (exact_match_itr != hint_paths.end())
    {
        match_itr = exact_match_itr;
        return true;
    }

    for (auto itr = hint_paths.begin(); itr != hint_paths.end(); itr++)
    {
        if (strncmp(relpath.c_str(), itr->first.c_str(), relpath.length()) == 0)
        {
            // Partial match found.
            match_itr = hint_paths.end();
            return true;
        }
    }

    return false; // Not found at all.
}

} // namespace statefs