#ifndef _STATEFS_HASHMAP_BUILDER_
#define _STATEFS_HASHMAP_BUILDER_

#include <string>
#include <list>
#include <map>
#include <vector>
#include <unordered_set>
#include "hasher.hpp"
#include "state_common.hpp"

namespace statefs
{

class hashmap_builder
{
private:
    const statedir_context &ctx;
    // List of new block hash map sub directories created during the session.
    std::unordered_set<std::string> created_bhmapsubdirs;

    int read_blockhashmap(std::vector<char> &bhmapdata, std::string &hmapfile, const std::string &relpath);
    int get_blockindex(std::map<uint32_t, hasher::B2H> &idxmap, uint32_t &blockcount, const std::string &filerelpath);
    int update_hashes(
        hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
        const uint32_t blockcount, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmapdata);
    int compute_blockhash(hasher::B2H &hash, uint32_t blockid, int filefd, const std::string &relpath);
    int write_blockhashmap(const std::string &bhmapfile, const hasher::B2H *hashes, const off_t hashes_size);
    int update_hashtree_entry(hasher::B2H &parentdirhash, const bool oldbhmap_exists, const hasher::B2H oldfilehash, const hasher::B2H newfilehash, const std::string &bhmapfile, const std::string &relpath);

public:
    hashmap_builder(const statedir_context &ctx);
    int generate_hashmap_forfile(hasher::B2H &parentdirhash, const std::string &filepath);
    int remove_hashmapfile(hasher::B2H &parentdirhash, const std::string &filepath);
};

} // namespace statefs

#endif
