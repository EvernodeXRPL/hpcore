#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <cmath>
#include <boost/filesystem.hpp>
#include "state_common.hpp"
#include "hashmap_builder.hpp"
#include "hasher.hpp"

namespace statefs
{

hashmap_builder::hashmap_builder(const statedir_context &ctx) : ctx(ctx)
{
}

int hashmap_builder::generate_hashmap_forfile(hasher::B2H &parentdirhash, const std::string &filepath)
{
    // We attempt to avoid a full rebuild of the block hash map file when possible.
    // For this optimisation, both the block hash map (.bhmap) file and the
    // delta block index (.bindex) file must exist.

    // If the block index exists, we generate/update the hashmap file with the aid of that.
    // Block index file contains the updated blockids. If not, we simply rehash all the blocks.

    std::string relpath = get_relpath(filepath, ctx.datadir);

    // Open the actual data file and calculate the block count.
    int orifd = open(filepath.data(), O_RDONLY);
    if (orifd == -1)
    {
        std::cerr << errno << ": Open failed " << filepath << '\n';
        return -1;
    }
    const off_t orifilelength = lseek(orifd, 0, SEEK_END);
    uint32_t blockcount = ceil((double)orifilelength / (double)BLOCK_SIZE);

    // Attempt to read the existing block hash map file.
    std::string bhmapfile;
    std::vector<char> bhmapdata;
    if (read_blockhashmap(bhmapdata, bhmapfile, relpath) == -1)
        return -1;

    hasher::B2H oldfilehash = {0, 0, 0, 0};
    if (!bhmapdata.empty())
        memcpy(&oldfilehash, bhmapdata.data(), hasher::HASH_SIZE);

    // Attempt to read the delta block index file.
    std::map<uint32_t, hasher::B2H> bindex;
    if (get_blockindex(bindex, blockcount, relpath) == -1)
        return -1;

    // Array to contain the updated block hashes.
    hasher::B2H hashes[1 + blockcount]; // slot 0 is for the root hash.
    const size_t hashes_size = (1 + blockcount) * hasher::HASH_SIZE;
    
    if (update_hashes(hashes, hashes_size, relpath, orifd, blockcount, bindex, bhmapdata) == -1)
        return -1;

    if (write_blockhashmap(bhmapfile, hashes, hashes_size) == -1)
        return -1;

    if (update_hashtree_entry(parentdirhash, !bhmapdata.empty(), oldfilehash, hashes[0], bhmapfile, relpath) == -1)
        return -1;

    return 0;
}

int hashmap_builder::read_blockhashmap(std::vector<char> &bhmapdata, std::string &bhmapfile, const std::string &relpath)
{
    bhmapfile.reserve(ctx.blockhashmapdir.length() + relpath.length() + HASHMAP_EXT_LEN);
    bhmapfile.append(ctx.blockhashmapdir).append(relpath).append(HASHMAP_EXT);

    if (boost::filesystem::exists(bhmapfile))
    {
        int hmapfd = open(bhmapfile.c_str(), O_RDONLY);
        if (hmapfd == -1)
        {
            std::cerr << errno << ": Open failed " << bhmapfile << '\n';
            return -1;
        }

        off_t size = lseek(hmapfd, 0, SEEK_END);
        bhmapdata.resize(size);

        if (pread(hmapfd, bhmapdata.data(), size, 0) == -1)
        {
            std::cerr << errno << ": Read failed " << bhmapfile << '\n';
            return -1;
        }
    }
    else
    {
        // Create directory tree if not exist so we are able to create the hashmap files.
        boost::filesystem::path hmapsubdir = boost::filesystem::path(bhmapfile).parent_path();
        if (created_bhmapsubdirs.count(hmapsubdir.string()) == 0)
        {
            boost::filesystem::create_directories(hmapsubdir);
            created_bhmapsubdirs.emplace(hmapsubdir.string());
        }
    }

    return 0;
}

int hashmap_builder::get_blockindex(std::map<uint32_t, hasher::B2H> &idxmap, uint32_t &blockcount, const std::string &filerelpath)
{
    std::string bindexfile;
    bindexfile.reserve(ctx.deltadir.length() + filerelpath.length() + BLOCKINDEX_EXT_LEN);
    bindexfile.append(ctx.deltadir).append(filerelpath).append(BLOCKINDEX_EXT);

    if (boost::filesystem::exists(bindexfile))
    {
        std::ifstream infile(bindexfile, std::ios::binary | std::ios::ate);
        std::streamsize idxsize = infile.tellg();
        infile.seekg(0, std::ios::beg);

        // Read the block index file into a vector.
        std::vector<char> bindex(idxsize);
        if (infile.read(bindex.data(), idxsize))
        {
            // First 8 bytes contain the original file length. Skip it.
            // Skip the first 8 bytes and loop through index entries.
            for (uint32_t idxoffset = 8; idxoffset < bindex.size();)
            {
                // Read the block no. (4 bytes) of where this block is from in the original file.
                uint32_t blockno = 0;
                memcpy(&blockno, bindex.data() + idxoffset, 4);
                idxoffset += 12; // Skip the cached block offset (8 bytes)

                // Read the block hash (32 bytes).
                hasher::B2H hash;
                memcpy(&hash, bindex.data() + idxoffset, 32);
                idxoffset += 32;

                idxmap.try_emplace(blockno, hash);
            }
        }
        else
        {
            std::cerr << errno << ": Read failed " << bindexfile << '\n';
            return -1;
        }

        infile.close();
    }

    return 0;
}

int hashmap_builder::update_hashes(
    hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
    const uint32_t blockcount, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmapdata)
{
    // If both existing delta block index and block hash map is available, we can just overlay the
    // changed block hashes (mentioned in the delta block index) on top of the old block hashes.
    if (!bhmapdata.empty() && !bindex.empty())
    {
        // Load old hashes.
        memcpy(hashes, bhmapdata.data(), hashes_size < bhmapdata.size() ? hashes_size : bhmapdata.size());

        // Refer to the block index and rehash the changed blocks.
        for (const auto [blockid, oldhash] : bindex)
        {
            if (compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
                return -1;
        }
    }
    else
    {
        //block index is empty. So we need to rehash the entire file.
        for (uint32_t blockid = 0; blockid < blockcount; blockid++)
        {
            if (compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
                return -1;
        }
    }

    // Calculate the new file hash: filehash = HASH(filename + XOR(block hashes))
    hasher::B2H filehash{0, 0, 0, 0};
    for (int i = 1; i < blockcount; i++)
        filehash ^= hashes[i];

    // Rehash the file hash with filename included.
    const std::string filename = boost::filesystem::path(relpath.data()).filename().string();
    filehash = hasher::hash(filename.c_str(), filename.length(), &filehash, hasher::HASH_SIZE);

    hashes[0] = filehash;
    return 0;
}

int hashmap_builder::compute_blockhash(hasher::B2H &hash, uint32_t blockid, int filefd, const std::string &relpath)
{
    char block[BLOCK_SIZE];
    const off_t blockoffset = BLOCK_SIZE * blockid;
    if (pread(filefd, block, BLOCK_SIZE, blockoffset) == -1)
    {
        std::cerr << errno << ": Read failed " << relpath << '\n';
        return -1;
    }

    hash = hasher::hash(&blockoffset, 8, block, BLOCK_SIZE);
    return 0;
}

int hashmap_builder::write_blockhashmap(const std::string &bhmapfile, const hasher::B2H *hashes, const off_t hashes_size)
{
    int hmapfd = open(bhmapfile.c_str(), O_RDWR | O_TRUNC | O_CREAT, FILE_PERMS);
    if (hmapfd == -1)
    {
        std::cerr << errno << ": Open failed " << bhmapfile << '\n';
        return -1;
    }

    // Write the updated hash list into the block hash map file.
    if (pwrite(hmapfd, hashes, hashes_size, 0) == -1)
    {
        std::cerr << errno << ": Write failed " << bhmapfile << '\n';
        return -1;
    }
}

int hashmap_builder::update_hashtree_entry(hasher::B2H &parentdirhash, const bool oldbhmap_exists, const hasher::B2H oldfilehash, const hasher::B2H newfilehash, const std::string &bhmapfile, const std::string &relpath)
{
    std::string hardlinkdir(ctx.hashtreedir);
    const std::string relpathdir = boost::filesystem::path(relpath).parent_path().string();

    hardlinkdir.append(relpathdir);
    if (relpathdir != "/")
        hardlinkdir.append("/");

    std::stringstream newhlpath;
    newhlpath << hardlinkdir << newfilehash << ".rh";

    if (oldbhmap_exists)
    {
        // Rename the existing hard link if old block hash map existed.
        // We thereby assume the old hard link also existed.
        std::stringstream oldhlpath;
        oldhlpath << hardlinkdir << oldfilehash << ".rh";
        if (rename(oldhlpath.str().c_str(), newhlpath.str().c_str()) == -1)
            return -1;

        // Subtract the old root hash and add the new root hash from the parent dir hash.
        parentdirhash ^= oldfilehash;
        parentdirhash ^= newfilehash;
    }
    else
    {
        // Create a new hard link with new root hash as the name.
        if (link(bhmapfile.c_str(), newhlpath.str().c_str()) == -1)
            return -1;

        // Add the new root hash to parent hash.
        parentdirhash ^= newfilehash;
    }

    return 0;
}

int hashmap_builder::remove_hashmapfile(hasher::B2H &parentdirhash, const std::string &bhmapfile)
{
    if (boost::filesystem::exists(bhmapfile))
    {
        int hmapfd = open(bhmapfile.data(), O_RDONLY);
        if (hmapfd == -1)
        {
            std::cerr << errno << ": Open failed " << bhmapfile << '\n';
            return -1;
        }

        hasher::B2H filehash;
        if (read(hmapfd, &filehash, hasher::HASH_SIZE) == -1)
        {
            std::cerr << errno << ": Read failed " << bhmapfile << '\n';
            return -1;
        }

        // Delete the .bhmap file.
        if (remove(bhmapfile.c_str()) == -1)
        {
            std::cerr << errno << ": Delete failed " << bhmapfile << '\n';
            return -1;
        }

        // Delete the hardlink of the .bhmap file.
        std::string hardlinkdir(ctx.hashtreedir);
        const std::string relpath = get_relpath(bhmapfile, ctx.blockhashmapdir);
        const std::string relpathdir = boost::filesystem::path(relpath).parent_path().string();

        hardlinkdir.append(relpathdir);
        if (relpathdir != "/")
            hardlinkdir.append("/");

        std::stringstream hlpath;
        hlpath << hardlinkdir << filehash << ".rh";
        if (remove(hlpath.str().c_str()) == -1)
        {
            std::cerr << errno << ": Delete failed for halrd link " << filehash << " of " << bhmapfile << '\n';
            return -1;
        }

        // XOR parent dir hash with file hash so the file hash gets removed from parent dir hash.
        parentdirhash ^= filehash;
    }

    return 0;
}

} // namespace statefs