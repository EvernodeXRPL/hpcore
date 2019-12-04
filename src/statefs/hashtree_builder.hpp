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
    const statedir_context ctx;
    hashmap_builder hmapbuilder;

    // Hint path map with parent dir as key and list of file paths under each parent dir.
    hintpath_map hintpaths;
    bool force_rebuild_all;
    bool hintmode;
    bool removal_mode;
    std::string traversel_rootdir;
    std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> fileblockindex;

    // List of new root hash map sub directories created during the session.
    std::unordered_set<std::string> created_htreesubdirs;

    int traverse_and_generate(hasher::B2H &roothash);
    int update_hashtree(hasher::B2H &roothash);
    int update_hashtree_fordir(hasher::B2H &parentdirhash, const std::string &relpath, const hintpath_map::iterator hintdir_itr, const bool isrootlevel);

    hasher::B2H get_existingdirhash(const std::string &dirhashfile);
    int save_dirhash(const std::string &dirhashfile, hasher::B2H dirhash);
    bool should_process_dir(hintpath_map::iterator &hintsubdir_itr, const std::string &dirpath);
    bool should_process_file(const hintpath_map::iterator hintdir_itr, const std::string filepath);
    int process_file(hasher::B2H &parentdirhash, const std::string &filepath, const std::string &htreedirpath);
    int update_hashtree_entry(hasher::B2H &parentdirhash, const bool oldbhmap_exists, const hasher::B2H oldfilehash, const hasher::B2H newfilehash, const std::string &bhmapfile, const std::string &relpath);
    void populate_hintpaths_from_idxfile(const char *const idxfile);
    void insert_hintpath(const std::string &relpath);
    bool get_hinteddir_match(hintpath_map::iterator &matchitr, const std::string &dirpath);

public:
    hashtree_builder(const statedir_context &ctx);
    int generate(hasher::B2H &roothash);
    int generate(hasher::B2H &roothash, const bool force_all);
    int generate(hasher::B2H &roothash, const std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> &touchedfiles);
};

} // namespace statefs

#endif
