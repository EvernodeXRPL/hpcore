#include "../pchheader.hpp"
#include "hashtree_builder.hpp"
#include "state_restore.hpp"
#include "state_common.hpp"

namespace statefs
{

hashtree_builder::hashtree_builder(const statedir_context &ctx) : ctx(ctx), hmapbuilder(ctx)
{
}

int hashtree_builder::generate()
{
    // Load modified file path hints if available.
    populate_hintpaths(IDX_TOUCHEDFILES);
    populate_hintpaths(IDX_NEWFILES);
    hintmode = !hintpaths.empty();

    traversel_rootdir = ctx.datadir;
    removal_mode = false;
    update_hashtree();

    // If there are any remaining hint files directly under this directory, that means
    // those files are no longer there. So we need to delete the corresponding .bhmap and rh files
    // and adjust the directory hash accordingly.
    if (hintmode && !hintpaths.empty())
    {
        traversel_rootdir = ctx.blockhashmapdir;
        removal_mode = true;
        update_hashtree();
    }

    return 0;
}

int hashtree_builder::update_hashtree()
{
    hintpath_map::iterator hintdir_itr = hintpaths.end();
    if (!should_process_dir(hintdir_itr, traversel_rootdir))
        return 0;

    hasher::B2H emptyhash{0, 0, 0, 0};
    if (update_hashtree_fordir(emptyhash, traversel_rootdir, hintdir_itr, true) == -1)
        return -1;

    return 0;
}

int hashtree_builder::update_hashtree_fordir(hasher::B2H &parentdirhash, const std::string &dirpath, const hintpath_map::iterator hintdir_itr, const bool isrootlevel)
{
    const std::string htreedirpath = switch_basepath(dirpath, traversel_rootdir, ctx.hashtreedir);

    // Load current dir hash if exist.
    const std::string dirhashfile = htreedirpath + "/" + DIRHASH_FNAME;
    hasher::B2H dirhash = get_existingdirhash(dirhashfile);

    // Remember the dir hash before we mutate it.
    hasher::B2H original_dirhash = dirhash;

    // Iterate files/subdirs inside this dir.
    const boost::filesystem::directory_iterator itrend;
    for (boost::filesystem::directory_iterator itr(dirpath); itr != itrend; itr++)
    {
        const bool isdir = boost::filesystem::is_directory(itr->path());
        const std::string pathstr = itr->path().string();

        if (isdir)
        {
            hintpath_map::iterator hintsubdir_itr = hintpaths.end();
            if (!should_process_dir(hintsubdir_itr, pathstr))
                continue;

            if (update_hashtree_fordir(dirhash, pathstr, hintsubdir_itr, false) == -1)
                return -1;
        }
        else
        {
            if (!should_process_file(hintdir_itr, pathstr))
                continue;

            if (process_file(dirhash, pathstr, htreedirpath) == -1)
                return -1;
        }
    }

    // If there are no more files in the hint dir, delete the hint dir entry as well.
    if (hintdir_itr != hintpaths.end() && hintdir_itr->second.empty())
        hintpaths.erase(hintdir_itr);

    // In removalmode, we check whether the dir is empty. If so we remove the dir as well.
    if (removal_mode && boost::filesystem::is_empty(dirpath))
    {
        // We remove the dirs if we are below root level only.
        // Otherwise we only remove root dir.hash file.
        if (!isrootlevel)
        {
            boost::filesystem::remove_all(dirpath);
            boost::filesystem::remove_all(htreedirpath);
        }
        else
        {
            boost::filesystem::remove(dirhashfile);
        }

        // Subtract the original dir hash from the parent dir hash.
        parentdirhash ^= original_dirhash;
    }
    else if (dirhash != original_dirhash)
    {
        // If dir hash has changed, write it back to dir hash file.
        if (save_dirhash(dirhashfile, dirhash) == -1)
            return -1;

        // Also update the parent dir hash by subtracting the old hash and adding the new hash.
        parentdirhash ^= original_dirhash;
        parentdirhash ^= dirhash;
    }

    return 0;
}

hasher::B2H hashtree_builder::get_existingdirhash(const std::string &dirhashfile)
{
    // Load current dir hash if exist.
    hasher::B2H dirhash{0, 0, 0, 0};
    int dirhashfd = open(dirhashfile.c_str(), O_RDONLY);
    if (dirhashfd > 0)
    {
        read(dirhashfd, &dirhash, hasher::HASH_SIZE);
        close(dirhashfd);
    }
    return dirhash;
}

int hashtree_builder::save_dirhash(const std::string &dirhashfile, hasher::B2H dirhash)
{
    int dirhashfd = open(dirhashfile.c_str(), O_RDWR | O_TRUNC | O_CREAT, FILE_PERMS);
    if (dirhashfd == -1)
        return -1;

    if (write(dirhashfd, &dirhash, hasher::HASH_SIZE) == -1)
    {
        close(dirhashfd);
        return -1;
    }

    close(dirhashfd);
    return 0;
}

inline bool hashtree_builder::should_process_dir(hintpath_map::iterator &dir_itr, const std::string &dirpath)
{
    return (hintmode ? get_hinteddir_match(dir_itr, dirpath) : true);
}

bool hashtree_builder::should_process_file(const hintpath_map::iterator hintdir_itr, const std::string filepath)
{
    if (hintmode)
    {
        if (hintdir_itr == hintpaths.end())
            return false;

        std::string relpath = get_relpath(filepath, traversel_rootdir);

        // If in removal mode, we are traversing .bhmap files. Hence we should truncate .bhmap extension
        // before we search for the path in file hints.
        if (removal_mode)
            relpath = relpath.substr(0, relpath.length() - HASHMAP_EXT_LEN);

        std::unordered_set<std::string> &hintfiles = hintdir_itr->second;
        const auto hintfile_itr = hintfiles.find(relpath);
        if (hintfile_itr == hintfiles.end())
            return false;

        // Erase the visiting filepath from hint files.
        hintfiles.erase(hintfile_itr);
    }
    return true;
}

int hashtree_builder::process_file(hasher::B2H &parentdirhash, const std::string &filepath, const std::string &htreedirpath)
{
    if (!removal_mode)
    {
        // Create directory tree if not exist so we are able to create the file root hash files (hard links).
        if (created_htreesubdirs.count(htreedirpath) == 0)
        {
            boost::filesystem::create_directories(htreedirpath);
            created_htreesubdirs.emplace(htreedirpath);
        }

        if (hmapbuilder.generate_hashmap_forfile(parentdirhash, filepath) == -1)
            return -1;
    }
    else
    {
        if (hmapbuilder.remove_hashmapfile(parentdirhash, filepath) == -1)
            return -1;
    }

    return 0;
}

void hashtree_builder::populate_hintpaths(const char *const idxfile)
{
    std::ifstream infile(std::string(ctx.deltadir).append(idxfile));
    if (!infile.fail())
    {
        for (std::string relpath; std::getline(infile, relpath);)
        {
            std::string parentdir = boost::filesystem::path(relpath).parent_path().string();
            hintpaths[parentdir].emplace(relpath);
        }
        infile.close();
    }
}

bool hashtree_builder::get_hinteddir_match(hintpath_map::iterator &matchitr, const std::string &dirpath)
{
    // First check whether there's an exact match. If not check for a partial match.
    // Exact match will return the iterator. Partial match or not found will return end() iterator.
    const std::string relpath = get_relpath(dirpath, traversel_rootdir);
    const auto exactmatchitr = hintpaths.find(relpath);

    if (exactmatchitr != hintpaths.end())
    {
        matchitr = exactmatchitr;
        return true;
    }

    for (auto itr = hintpaths.begin(); itr != hintpaths.end(); itr++)
    {
        if (strncmp(relpath.c_str(), itr->first.c_str(), relpath.length()) == 0)
        {
            // Partial match found.
            matchitr = hintpaths.end();
            return true;
        }
    }

    return false; // Not found at all.
}

} // namespace statefs