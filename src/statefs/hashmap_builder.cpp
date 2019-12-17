#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "state_common.hpp"
#include "hashmap_builder.hpp"
#include "hasher.hpp"

namespace statefs
{

/**
 * Hashmap builder class is responsible for updating file hash based on the modified blocks of a file.
 */

hashmap_builder::hashmap_builder(const statedir_context &ctx) : ctx(ctx)
{
}

/**
 * Generates/updates the block hash map for a file and updates the parent dir hash accordingly as well.
 * @param parent_dir_hash Hash of the parent directory. This will be updated of the file hash was updated.
 * @param filepath The actual state file path.
 */
int hashmap_builder::generate_hashmap_forfile(hasher::B2H &parent_dir_hash, const std::string &filepath, const std::string &file_relpath, const std::map<uint32_t, hasher::B2H> &changed_blocks)
{
    // We attempt to avoid a full rebuild of the block hash map file when possible.
    // For this optimisation, both the block hash map (.bhmap) file and the
    // delta block index must exist.

    // Block index may be provided as an argument. If it is empty we attempt to read from the
    // .bindex file from the state checkpoint delta.

    // If the block index exists, we generate/update the hashmap file with the aid of that.
    // Block index file contains the updated blockids. If not, we simply rehash all the blocks.

    // Open the actual data file and calculate the block count.
    int orifd = open(filepath.data(), O_RDONLY);
    if (orifd == -1)
    {
        LOG_ERR << errno << ": Open failed " << filepath;
        return -1;
    }
    const off_t file_length = lseek(orifd, 0, SEEK_END);
    const uint32_t block_count = ceil((double)file_length / (double)BLOCK_SIZE);

    // Attempt to read the existing block hash map file.
    std::string bhmap_file;
    std::vector<char> bhmap_data;
    if (read_block_hashmap(bhmap_data, bhmap_file, file_relpath) == -1)
    {
        close(orifd);
        return -1;
    }

    hasher::B2H old_file_hash = hasher::B2H_empty;
    if (!bhmap_data.empty())
        memcpy(&old_file_hash, bhmap_data.data(), hasher::HASH_SIZE);

    // Array to contain the updated block hashes. Slot 0 is for the root hash.
    // Allocating hash array on the heap to avoid filling limited stack space.
    std::unique_ptr<hasher::B2H[]> hashes = std::make_unique<hasher::B2H[]>(1 + block_count);
    const size_t hashes_size = (1 + block_count) * hasher::HASH_SIZE;

    if (changed_blocks.empty())
    {
        // Attempt to read the delta block index file.
        std::map<uint32_t, hasher::B2H> bindex;
        uint32_t original_block_count;
        if (get_block_index(bindex, original_block_count, file_relpath) == -1)
        {
            close(orifd);
            return -1;
        }

        if (update_hashes_with_backup_blockhints(hashes.get(), hashes_size, file_relpath, orifd, block_count, original_block_count, bindex, bhmap_data) == -1)
        {
            close(orifd);
            return -1;
        }
    }
    else
    {
        if (update_hashes_with_changed_block_hints(hashes.get(), hashes_size, file_relpath, orifd, block_count, changed_blocks, bhmap_data) == -1)
        {
            close(orifd);
            return -1;
        }
    }

    close(orifd);

    if (write_block_hashmap(bhmap_file, hashes.get(), hashes_size) == -1)
        return -1;

    if (update_hashtree_entry(parent_dir_hash, !bhmap_data.empty(), old_file_hash, hashes[0], bhmap_file, file_relpath) == -1)
        return -1;

    return 0;
}

int hashmap_builder::read_block_hashmap(std::vector<char> &bhmap_data, std::string &bhmap_file, const std::string &relpath)
{
    bhmap_file.reserve(ctx.block_hashmap_dir.length() + relpath.length() + HASHMAP_EXT_LEN);
    bhmap_file.append(ctx.block_hashmap_dir).append(relpath).append(HASHMAP_EXT);

    if (boost::filesystem::exists(bhmap_file))
    {
        int hmapfd = open(bhmap_file.c_str(), O_RDONLY);
        if (hmapfd == -1)
        {
            LOG_ERR << errno << ": Open failed " << bhmap_file;
            return -1;
        }

        off_t size = lseek(hmapfd, 0, SEEK_END);
        bhmap_data.resize(size);

        if (pread(hmapfd, bhmap_data.data(), size, 0) == -1)
        {
            LOG_ERR << errno << ": Read failed " << bhmap_file;
            close(hmapfd);
            return -1;
        }

        close(hmapfd);
    }
    else
    {
        // Create directory tree if not exist so we are able to create the hashmap files.
        boost::filesystem::path hmapsubdir = boost::filesystem::path(bhmap_file).parent_path();
        if (created_bhmapsubdirs.count(hmapsubdir.string()) == 0)
        {
            boost::filesystem::create_directories(hmapsubdir);
            created_bhmapsubdirs.emplace(hmapsubdir.string());
        }
    }

    return 0;
}

int hashmap_builder::get_block_index(std::map<uint32_t, hasher::B2H> &idxmap, uint32_t &totalblockcount, const std::string &file_relpath)
{
    std::string bindexfile;
    bindexfile.reserve(ctx.deltadir.length() + file_relpath.length() + BLOCKINDEX_EXT_LEN);
    bindexfile.append(ctx.deltadir).append(file_relpath).append(BLOCKINDEX_EXT);

    if (boost::filesystem::exists(bindexfile))
    {
        std::ifstream infile(bindexfile, std::ios::binary | std::ios::ate);
        std::streamsize idxsize = infile.tellg();
        infile.seekg(0, std::ios::beg);

        // Read the block index file into a vector.
        std::vector<char> bindex(idxsize);
        if (infile.read(bindex.data(), idxsize))
        {
            // First 8 bytes contain the original file length.
            off_t orifilelen;
            memcpy(&orifilelen, bindex.data(), 8);
            totalblockcount = ceil((double)orifilelen / (double)BLOCK_SIZE);

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
            LOG_ERR << errno << ": Read failed " << bindexfile;
            return -1;
        }

        infile.close();
    }

    return 0;
}

int hashmap_builder::update_hashes_with_backup_blockhints(
    hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
    const uint32_t block_count, const uint32_t original_block_count, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmap_data)
{
    uint32_t nohint_blockstart = 0;

    // If both existing delta block index and block hash map is available, we can just overlay the
    // changed block hashes (mentioned in the delta block index) on top of the old block hashes.
    // This would prevent unncessarily hashing lot of blocks.
    if (!bhmap_data.empty() && !bindex.empty())
    {
        // Load old hashes.
        memcpy(hashes, bhmap_data.data(), hashes_size < bhmap_data.size() ? hashes_size : bhmap_data.size());

        // Refer to the block index and rehash the changed blocks.
        for (const auto [blockid, oldhash] : bindex)
        {
            // If the blockid from the block index is no longer there, that means the current file is
            // shorter than the previous version. So we can stop hashing at this point.
            if (blockid >= block_count)
                break;

            if (compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
                return -1;
        }

        // If the current file has more blocks than the previous version, we need to hash those
        // additional blocks as well.
        if (block_count > original_block_count)
            nohint_blockstart = original_block_count;
        else
            nohint_blockstart = block_count; // No additional blocks remaining.
    }

    //Hash any additional blocks that has to be hashed without the guidance of block index.
    for (uint32_t blockid = nohint_blockstart; blockid < block_count; blockid++)
    {
        if (compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
            return -1;
    }

    // Calculate the new file hash: filehash = HASH(filename + XOR(block hashes))
    hasher::B2H filehash = hasher::B2H_empty;
    for (int i = 1; i <= block_count; i++)
        filehash ^= hashes[i];

    // Rehash the file hash with filename included.
    const std::string filename = boost::filesystem::path(relpath.data()).filename().string();
    filehash = hasher::hash(filename.c_str(), filename.length(), &filehash, hasher::HASH_SIZE);

    hashes[0] = filehash;
    return 0;
}

int hashmap_builder::update_hashes_with_changed_block_hints(
    hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd,
    const uint32_t block_count, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmap_data)
{
    // If both existing delta block index and block hash map is available, we can just overlay the
    // changed block hashes (mentioned in the delta block index) on top of the old block hashes.
    // This would prevent unncessarily hashing lot of blocks.

    if (!bindex.empty())
    {
        // Load old hashes if exists.
        if (!bhmap_data.empty())
            memcpy(hashes, bhmap_data.data(), hashes_size < bhmap_data.size() ? hashes_size : bhmap_data.size());

        // Refer to the block index and overlay the new hash into the hashes array.
        for (const auto [blockid, newhash] : bindex)
            hashes[blockid + 1] = newhash;

        // If the block hash map didn't existed, we need to calculate and fill the unchanged block hashes from the actual file.
        if (bhmap_data.empty())
        {
            for (uint32_t blockid = 0; blockid < block_count; blockid++)
            {
                if (bindex.count(blockid) == 0 && compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
                    return -1;
            }
        }
    }
    else
    {
        // If we don't have the changed block index, we have to hash the entire file blocks again.
        for (uint32_t blockid = 0; blockid < block_count; blockid++)
        {
            if (compute_blockhash(hashes[blockid + 1], blockid, orifd, relpath) == -1)
                return -1;
        }
    }

    // Calculate the new file hash: filehash = HASH(filename + XOR(block hashes))
    hasher::B2H filehash = hasher::B2H_empty;
    for (int i = 1; i <= block_count; i++)
        filehash ^= hashes[i];

    // Rehash the file hash with filename included.
    const std::string filename = boost::filesystem::path(relpath.data()).filename().string();
    filehash = hasher::hash(filename.c_str(), filename.length(), &filehash, hasher::HASH_SIZE);

    hashes[0] = filehash;
    return 0;
}

int hashmap_builder::compute_blockhash(hasher::B2H &hash, uint32_t blockid, int filefd, const std::string &relpath)
{
    // Allocating block buffer on the heap to avoid filling limited stack space.
    std::unique_ptr<char[]> blockbuf = std::make_unique<char[]>(BLOCK_SIZE);
    const off_t blockoffset = BLOCK_SIZE * blockid;
    size_t bytesread = pread(filefd, blockbuf.get(), BLOCK_SIZE, blockoffset);
    if (bytesread == -1)
    {
        LOG_ERR << errno << ": Read failed " << relpath;
        return -1;
    }

    hash = hasher::hash(&blockoffset, 8, blockbuf.get(), bytesread);
    return 0;
}

int hashmap_builder::write_block_hashmap(const std::string &bhmap_file, const hasher::B2H *hashes, const off_t hashes_size)
{
    int hmapfd = open(bhmap_file.c_str(), O_RDWR | O_TRUNC | O_CREAT, FILE_PERMS);
    if (hmapfd == -1)
    {
        LOG_ERR << errno << ": Open failed " << bhmap_file;
        return -1;
    }

    // Write the updated hash list into the block hash map file.
    if (pwrite(hmapfd, hashes, hashes_size, 0) == -1)
    {
        LOG_ERR << errno << ": Write failed " << bhmap_file;
        close(hmapfd);
        return -1;
    }

    if (ftruncate(hmapfd, hashes_size) == -1)
    {
        LOG_ERR << errno << ": Truncate failed " << bhmap_file;
        close(hmapfd);
        return -1;
    }

    close(hmapfd);
}

int hashmap_builder::update_hashtree_entry(hasher::B2H &parent_dir_hash, const bool oldbhmap_exists, const hasher::B2H old_file_hash, const hasher::B2H newfilehash, const std::string &bhmap_file, const std::string &relpath)
{
    std::string hardlinkdir(ctx.hashtreedir);
    const std::string relpathdir = boost::filesystem::path(relpath).parent_path().string();

    hardlinkdir.append(relpathdir);
    if (relpathdir != "/")
        hardlinkdir.append("/");

    std::stringstream newhlpath;
    newhlpath << hardlinkdir << newfilehash << ".rh";

    // TODO: Even though we maintain hardlinks named after the file hash, we don't actually utilize them elsewhere.
    // The intention is to be able to get a hash listing of the entire directory. Such ability is useful to serve state
    // requests. However since state requests need the file name along with the hash we have to resort to iterating each
    // .bhmap file and reading the file hash from first 32 bytes.

    if (oldbhmap_exists)
    {
        // Rename the existing hard link if old block hash map existed.
        // We thereby assume the old hard link also existed.
        std::stringstream oldhlpath;
        oldhlpath << hardlinkdir << old_file_hash << ".rh";
        if (rename(oldhlpath.str().c_str(), newhlpath.str().c_str()) == -1)
            return -1;

        // Subtract the old root hash and add the new root hash from the parent dir hash.
        parent_dir_hash ^= old_file_hash;
        parent_dir_hash ^= newfilehash;
    }
    else
    {
        // Create a new hard link with new root hash as the name.
        if (link(bhmap_file.c_str(), newhlpath.str().c_str()) == -1)
            return -1;

        // Add the new root hash to parent hash.
        parent_dir_hash ^= newfilehash;
    }

    return 0;
}

int hashmap_builder::remove_hashmapfile(hasher::B2H &parent_dir_hash, const std::string &bhmap_file)
{
    if (boost::filesystem::exists(bhmap_file))
    {
        int hmapfd = open(bhmap_file.data(), O_RDONLY);
        if (hmapfd == -1)
        {
            LOG_ERR << errno << ": Open failed " << bhmap_file;
            return -1;
        }

        hasher::B2H filehash;
        if (read(hmapfd, &filehash, hasher::HASH_SIZE) == -1)
        {
            LOG_ERR << errno << ": Read failed " << bhmap_file;
            close(hmapfd);
            return -1;
        }

        // Delete the .bhmap file.
        if (remove(bhmap_file.c_str()) == -1)
        {
            LOG_ERR << errno << ": Delete failed " << bhmap_file;
            close(hmapfd);
            return -1;
        }

        // Delete the hardlink of the .bhmap file.
        std::string hardlinkdir(ctx.hashtreedir);
        const std::string relpath = get_relpath(bhmap_file, ctx.block_hashmap_dir);
        const std::string relpathdir = boost::filesystem::path(relpath).parent_path().string();

        hardlinkdir.append(relpathdir);
        if (relpathdir != "/")
            hardlinkdir.append("/");

        std::stringstream hlpath;
        hlpath << hardlinkdir << filehash << ".rh";
        if (remove(hlpath.str().c_str()) == -1)
        {
            LOG_ERR << errno << ": Delete failed for hard link " << filehash << " of " << bhmap_file;
            close(hmapfd);
            return -1;
        }

        // XOR parent dir hash with file hash so the file hash gets removed from parent dir hash.
        parent_dir_hash ^= filehash;
        close(hmapfd);
    }

    return 0;
}

} // namespace statefs