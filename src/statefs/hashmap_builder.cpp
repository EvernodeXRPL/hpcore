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

hashmap_builder::hashmap_builder(const state_dir_context &ctx) : ctx(ctx)
{
}

/**
 * Generates/updates the block hash map for a file and updates the parent dir hash accordingly as well.
 * @param parent_dir_hash Hash of the parent directory. This will be updated of the file hash was updated.
 * @param filepath Full path to the actual state file.
 * @param file_relpath The relative path to the state file from the state data directory.
 * @param changed_blocks Index of changed blocks and the new hashes to be used as a hint.
 * @return 0 on success. -1 on failure.
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
        if (get_delta_block_index(bindex, original_block_count, file_relpath) == -1)
        {
            close(orifd);
            return -1;
        }

        if (update_hashes_with_backup_block_hints(hashes.get(), hashes_size, file_relpath, orifd, block_count, original_block_count, bindex, bhmap_data) == -1)
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

/**
 * Reads the block hash map of a given data file into the provided vector.
 * @param bhmap_data Vector to copy the block hash map contents.
 * @param bhmap_file The full path to the block hash map file pointed to by the relative path.
 * @param relpath The relative path of the actual data file.
 * @return 0 on success. -1 on failure.
 */
int hashmap_builder::read_block_hashmap(std::vector<char> &bhmap_data, std::string &bhmap_file, const std::string &relpath)
{
    bhmap_file.reserve(ctx.block_hashmap_dir.length() + relpath.length() + BLOCK_HASHMAP_EXT_LEN);
    bhmap_file.append(ctx.block_hashmap_dir).append(relpath).append(BLOCK_HASHMAP_EXT);

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

/**
 * Reads the delta block index of a file.
 * @param idxmap Map to copy the block index contents (block id --> hash).
 * @param total_block_count Reference to hold the total block count of the original data file.
 * @param file_relpath Relative path to the data file.
 * @return 0 on success. -1 on failure.
 */
int hashmap_builder::get_delta_block_index(std::map<uint32_t, hasher::B2H> &idxmap, uint32_t &total_block_count, const std::string &file_relpath)
{
    std::string bindexfile;
    bindexfile.reserve(ctx.delta_dir.length() + file_relpath.length() + BLOCK_INDEX_EXT_LEN);
    bindexfile.append(ctx.delta_dir).append(file_relpath).append(BLOCK_INDEX_EXT);

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
            total_block_count = ceil((double)orifilelen / (double)BLOCK_SIZE);

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

/**
 * Updates the hash map with the use of delta backup block ids.
 * @param hashes Pointer to the hash array to copy the block hashes after the update.
 * @param hashes_size Byte length of the hashes array.
 * @param relpath Relative path of the data file.
 * @param orifd An open file descriptor to the data file.
 * @param block_count Block count of the updated file.
 * @param original_block_count Original block count before the update.
 * @param bindex Delta backup block index map.
 * @param bhmap_data Contents of the existing block hash map.
 * @return 0 on success. -1 on failure.
 */
int hashmap_builder::update_hashes_with_backup_block_hints(
    hasher::B2H *hashes, const off_t hashes_size, const std::string &relpath, const int orifd, const uint32_t block_count,
    const uint32_t original_block_count, const std::map<uint32_t, hasher::B2H> &bindex, const std::vector<char> &bhmap_data)
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
        for (const auto [block_id, old_hash] : bindex)
        {
            // If the block_id from the block index is no longer there, that means the current file is
            // shorter than the previous version. So we can stop hashing at this point.
            if (block_id >= block_count)
                break;

            if (compute_blockhash(hashes[block_id + 1], block_id, orifd, relpath) == -1)
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
    for (uint32_t block_id = nohint_blockstart; block_id < block_count; block_id++)
    {
        if (compute_blockhash(hashes[block_id + 1], block_id, orifd, relpath) == -1)
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

/**
 * Updates the hash map with the use of list of updated block ids.
 * @param hashes Pointer to the hash array to copy the block hashes after the update.
 * @param hashes_size Byte length of the hashes array.
 * @param relpath Relative path of the data file.
 * @param orifd An open file descriptor to the data file.
 * @param block_count Block count of the updated file.
 * @param bindex Map of updated block ids and new hashes.
 * @param bhmap_data Contents of the existing block hash map.
 * @return 0 on success. -1 on failure.
 */
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
        for (const auto [block_id, new_hash] : bindex)
            hashes[block_id + 1] = new_hash;

        // If the block hash map didn't existed, we need to calculate and fill the unchanged block hashes from the actual file.
        if (bhmap_data.empty())
        {
            for (uint32_t block_id = 0; block_id < block_count; block_id++)
            {
                if (bindex.count(block_id) == 0 && compute_blockhash(hashes[block_id + 1], block_id, orifd, relpath) == -1)
                    return -1;
            }
        }
    }
    else
    {
        // If we don't have the changed block index, we have to hash the entire file blocks again.
        for (uint32_t block_id = 0; block_id < block_count; block_id++)
        {
            if (compute_blockhash(hashes[block_id + 1], block_id, orifd, relpath) == -1)
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

/**
 * Calculates the hash of the specified block id of a file.
 * @param hash Reference to assign the calculated hash.
 * @param block_id Id of the block to be hashed.
 * @param filefd Open file descriptor for the state data file.
 * @param relpath Relative path of the state data file.
 * @return 0 on success. -1 on failure.
 */
int hashmap_builder::compute_blockhash(hasher::B2H &hash, const uint32_t block_id, const int filefd, const std::string &relpath)
{
    // Allocating block buffer on the heap to avoid filling limited stack space.
    std::unique_ptr<char[]> block_buf = std::make_unique<char[]>(BLOCK_SIZE);
    const off_t block_offset = BLOCK_SIZE * block_id;
    size_t bytes_read = pread(filefd, block_buf.get(), BLOCK_SIZE, block_offset);
    if (bytes_read == -1)
    {
        LOG_ERR << errno << ": Read failed " << relpath;
        return -1;
    }

    hash = hasher::hash(&block_offset, 8, block_buf.get(), bytes_read);
    return 0;
}

/**
 * Saves the block hash map into the relevant .bhmap file.
 * @param bhmap_file Full path to the block hash map file.
 * @param hashes Pointer to the hashes array containing the root hash and block hashes.
 * @param hashes_size Byte length of the hashes array.
 * @return 0 on success. -1 on failure.
 */
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

/**
 * Updates a file hash and adjust parent dir hash of the hash tree.
 * @param parent_dir_hash Current hash of the parent dir. This will be assigned the new hash after the update.
 * @param old_bhmap_exists Whether the block hash map file already exists or not.
 * @param old_file_hash Old file hash. (0000 if this is a new file)
 * @param new_file_hash New file hash.
 * @param bhmap_file Full path to the block hash map file.
 * @param relpath Relative path to the state data file.
 * @return 0 on success. -1 on failure.
 */
int hashmap_builder::update_hashtree_entry(hasher::B2H &parent_dir_hash, const bool old_bhmap_exists, const hasher::B2H old_file_hash,
                                           const hasher::B2H new_file_hash, const std::string &bhmap_file, const std::string &relpath)
{
    std::string hardlink_dir(ctx.hashtree_dir);
    const std::string relpath_dir = boost::filesystem::path(relpath).parent_path().string();

    hardlink_dir.append(relpath_dir);
    if (relpath_dir != "/")
        hardlink_dir.append("/");

    std::stringstream new_hl_path;
    new_hl_path << hardlink_dir << new_file_hash << ".rh";

    // TODO: Even though we maintain hardlinks named after the file hash, we don't actually utilize them elsewhere.
    // The intention is to be able to get a hash listing of the entire directory. Such ability is useful to serve state
    // requests. However since state requests need the file name along with the hash we have to resort to iterating each
    // .bhmap file and reading the file hash from first 32 bytes.

    if (old_bhmap_exists)
    {
        // Rename the existing hard link if old block hash map existed.
        // We thereby assume the old hard link also existed.
        std::stringstream oldhlpath;
        oldhlpath << hardlink_dir << old_file_hash << ".rh";
        if (rename(oldhlpath.str().c_str(), new_hl_path.str().c_str()) == -1)
            return -1;

        // Subtract the old root hash and add the new root hash from the parent dir hash.
        parent_dir_hash ^= old_file_hash;
        parent_dir_hash ^= new_file_hash;
    }
    else
    {
        // Create a new hard link with new root hash as the name.
        if (link(bhmap_file.c_str(), new_hl_path.str().c_str()) == -1)
            return -1;

        // Add the new root hash to parent hash.
        parent_dir_hash ^= new_file_hash;
    }

    return 0;
}

/**
 * Removes an existing block hash map file. Caled when deleting a state data file.
 * @param parent_dir_hash Current hash of the parent dir. This will be assigned the new hash after the update.
 * @param Full path to the block hash map file.
 * @return 0 on success. -1 on failure.
 */
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
        std::string hardlink_dir(ctx.hashtree_dir);
        const std::string relpath = get_relpath(bhmap_file, ctx.block_hashmap_dir);
        const std::string relpath_dir = boost::filesystem::path(relpath).parent_path().string();

        hardlink_dir.append(relpath_dir);
        if (relpath_dir != "/")
            hardlink_dir.append("/");

        std::stringstream hlpath;
        hlpath << hardlink_dir << filehash << ".rh";
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