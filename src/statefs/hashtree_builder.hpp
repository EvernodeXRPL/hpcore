#ifndef _STATEFS_HASHTREE_BUILDER_
#define _STATEFS_HASHTREE_BUILDER_

#include <unordered_set>
#include "hasher.hpp"
#include "hashmap_builder.hpp"
#include "state_common.hpp"

namespace statefs
{

typedef std::unordered_map<std::string, std::unordered_set<std::string>> hintpath_map;

class hashtree_builder
{
private:
    const statedir_context &ctx;
    hashmap_builder hmapbuilder;

    // Hint path map with parent dir as key and list of file paths under each parent dir.
    hintpath_map hintpaths;
    bool hintmode;
    bool removal_mode;
    std::string traversel_rootdir;

    // List of new root hash map sub directories created during the session.
    std::unordered_set<std::string> created_htreesubdirs;

    int update_hashtree();
    int update_hashtree_fordir(hasher::B2H &parentdirhash, const std::string &relpath, const hintpath_map::iterator hintdir_itr, const bool isrootlevel);

    hasher::B2H get_existingdirhash(const std::string &dirhashfile);
    int save_dirhash(const std::string &dirhashfile, hasher::B2H dirhash);
    bool should_process_dir(hintpath_map::iterator &hintsubdir_itr, const std::string &dirpath);
    bool should_process_file(const hintpath_map::iterator hintdir_itr, const std::string filepath);
    int process_file(hasher::B2H &parentdirhash, const std::string &filepath, const std::string &htreedirpath);
    int update_hashtree_entry(hasher::B2H &parentdirhash, const bool oldbhmap_exists, const hasher::B2H oldfilehash, const hasher::B2H newfilehash, const std::string &bhmapfile, const std::string &relpath);
    void populate_hintpaths(const char *const idxfile);
    bool get_hinteddir_match(hintpath_map::iterator &matchitr, const std::string &dirpath);

public:
    hashtree_builder(const statedir_context &ctx);
    int generate();
};

} // namespace statefs

#endif
