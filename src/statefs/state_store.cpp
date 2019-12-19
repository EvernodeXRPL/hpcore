#include "../pchheader.hpp"
#include "hasher.hpp"
#include "state_common.hpp"
#include "hashtree_builder.hpp"
#include "state_store.hpp"
#include "../hplog.hpp"
#include "state_store.hpp"

namespace statefs
{

// Map of modified/deleted files with updated blockids and hashes (if modified).
std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touched_files;

/**
 * Checks whether the given directory exists in the state data directory.
 */
bool is_dir_exists(const std::string &dir_relpath)
{
    const std::string full_path = current_ctx.data_dir + dir_relpath;
    return boost::filesystem::exists(full_path);
}

/**
 * Retrieves the hash list of the file system entries at a given directory.
 * @return 0 on success. -1 on failure.
 */
int get_fs_entry_hashes(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries, const std::string &dir_relpath, const hasher::B2H expected_hash)
{
    // TODO: instead of iterating the data dir, we could simply query the hash tree directory
    // listing and get the hashes using the hardlink names straight away. But then we don't have
    // a way to get the file names. If we could implement a mechanism for that we could make this efficient.

    if (expected_hash != hasher::B2H_empty)
    {
        // Check whether the existing block hash matches expected hash.
        const std::string dir_hash_path = current_ctx.hashtree_dir + dir_relpath + DIR_HASH_FNAME;

        hasher::B2H existsing_hash;
        if (read_file_bytes(&existsing_hash, dir_hash_path.c_str(), 0, hasher::HASH_SIZE) == -1)
            return -1;
            
        if (existsing_hash != expected_hash)
            return -1;
    }

    const std::string full_path = current_ctx.data_dir + dir_relpath;
    for (const boost::filesystem::directory_entry &dentry : boost::filesystem::directory_iterator(full_path))
    {
        const boost::filesystem::path p = dentry.path();

        p2p::state_fs_hash_entry fs_entry;
        fs_entry.is_file = !boost::filesystem::is_directory(p);

        std::string fsentry_relpath = dir_relpath + p.filename().string();

        // Read the first 32 bytes of the .bhmap file or dir.hash file.

        std::string hash_path;

        if (fs_entry.is_file)
        {
            hash_path = current_ctx.block_hashmap_dir + fsentry_relpath + BLOCK_HASHMAP_EXT;
        }
        else
        {
            fsentry_relpath += "/";
            hash_path = current_ctx.hashtree_dir + fsentry_relpath + DIR_HASH_FNAME;
            // Skip the directory if it doesn't contain the dir.hash file.
            // By that we assume the directory is empty so we're not interested in it.
            if (!boost::filesystem::exists(hash_path))
                continue;
        }

        if (read_file_bytes(&fs_entry.hash, hash_path.c_str(), 0, hasher::HASH_SIZE) == -1)
            return -1;

        fs_entries.emplace(fsentry_relpath, std::move(fs_entry));
    }
    return 0;
}

/**
 * Retrieves the block hash map for a file.
 * @return 0 on success. -1 on failure.
 */
int get_block_hash_map(std::vector<uint8_t> &vec, const std::string &file_relpath, const hasher::B2H expected_hash)
{
    const std::string bhmap_path = current_ctx.block_hashmap_dir + file_relpath + BLOCK_HASHMAP_EXT;

    if (expected_hash != hasher::B2H_empty)
    {
        // Check whether the existing block hash matches expected hash.

        if (!boost::filesystem::exists(bhmap_path) || read_file_bytes_to_end(vec, bhmap_path.c_str(), 0) == -1)
            return -1;

        // Existing hash is the first 32 bytes of bhmap contents.
        hasher::B2H existing_hash = *reinterpret_cast<hasher::B2H *>(vec.data());
        if (existing_hash != expected_hash)
            return -1;

        // Return the bhmap bytes without the first 32 bytes.
        vec.erase(vec.begin(), vec.begin() + hasher::HASH_SIZE);
    }
    else
    {
        // Skip the file root hash and get the rest of the bytes.
        if (boost::filesystem::exists(bhmap_path) && read_file_bytes_to_end(vec, bhmap_path.c_str(), hasher::HASH_SIZE) == -1)
            return -1;
    }

    return 0;
}

/**
 * Retrieves the byte length of a file.
 * @return 0 on success. -1 on failure.
 */
int get_file_length(const std::string &file_relpath)
{
    std::string full_path = current_ctx.data_dir + file_relpath;
    int fd = open(full_path.c_str(), O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << " Open failed " << full_path;
        return -1;
    }

    const off_t total_len = lseek(fd, 0, SEEK_END);
    close(fd);

    return total_len;
}

/**
 * Retrieves the specified data block from a state file.
 * @return Number of bytes read on success. -1 on failure.
 */
int get_block(std::vector<uint8_t> &vec, const std::string &file_relpath, const uint32_t block_id, const hasher::B2H expected_hash)
{
    // Check whether the existing block hash matches expected hash.
    if (expected_hash != hasher::B2H_empty)
    {
        std::string bhmap_path = current_ctx.block_hashmap_dir + file_relpath + BLOCK_HASHMAP_EXT;
        hasher::B2H existing_hash = hasher::B2H_empty;

        if (read_file_bytes(&existing_hash, bhmap_path.c_str(), (block_id + 1) * hasher::HASH_SIZE, hasher::HASH_SIZE) == -1)
            return -1;

        if (existing_hash != expected_hash)
            return -1;
    }

    std::string full_path = current_ctx.data_dir + file_relpath;
    vec.resize(BLOCK_SIZE);
    int read_bytes = read_file_bytes(vec.data(), full_path.c_str(), block_id * BLOCK_SIZE, BLOCK_SIZE);

    if (read_bytes == -1)
        return -1;

    vec.resize(read_bytes);
    return read_bytes;
}

/**
 * Creates the specified directory in the state data directory.
 */
void create_dir(const std::string &dir_relpath)
{
    const std::string full_path = current_ctx.data_dir + dir_relpath;
    boost::filesystem::create_directories(full_path);
}

/**
 * Deletes all files within the specified state sub directory and marks the changes.
 * @return 0 on success. -1 on failure.
 */
int delete_dir(const std::string &dir_relpath)
{
    std::string full_dir_path = current_ctx.data_dir + dir_relpath;

    const boost::filesystem::directory_iterator itr_end;
    for (boost::filesystem::directory_iterator itr(full_dir_path); itr != itr_end; itr++)
    {
        boost::filesystem::path p = itr->path();

        if (!boost::filesystem::is_directory(p))
        {
            if (!boost::filesystem::remove(p))
                return -1;

            // Add the deleted file rel path to the touched files list.
            touched_files.emplace(
                get_relpath(p.string(), current_ctx.data_dir),
                std::map<uint32_t, hasher::B2H>());
        }
    }

    // Finally, delete the directory itself.
    boost::filesystem::remove_all(full_dir_path);

    return 0;
}

/**
 * Deletes the specified state file and marks the change.
 * @return 0 on success. -1 on failure.
 */
int delete_file(const std::string &file_relpath)
{
    std::string full_path = current_ctx.data_dir + file_relpath;
    if (!boost::filesystem::remove(full_path))
        return -1;

    touched_files.emplace(file_relpath, std::map<uint32_t, hasher::B2H>());
    return 0;
}

/**
 * Truncates the specified state file to the specified length and marks the change.
 * @return 0 on success. -1 on failure.
 */
int truncate_file(const std::string &file_relpath, const size_t newsize)
{
    std::string full_path = current_ctx.data_dir + file_relpath;
    int fd = open(full_path.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
    if (fd == -1)
    {
        LOG_ERR << errno << " Open failed " << full_path;
        return -1;
    }

    int ret = ftruncate(fd, newsize);
    close(fd);
    if (ret == -1)
    {
        LOG_ERR << errno << "Truncate failed " << full_path;
        return -1;
    }

    return 0;
}

/**
 * Writes the specified block to a file and marks the change.
 * @param file_relpath State data relative path of the file.
 * @param block_id Block id to replace/write.
 * @param buf The buffer containing data to be written.
 * @param len Length of the buffer.
 * @return 0 on success. -1 on failure.
 */
int write_block(const std::string &file_relpath, const uint32_t block_id, const void *buf, const size_t len)
{
    std::string full_path = current_ctx.data_dir + file_relpath;
    int fd = open(full_path.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
    if (fd == -1)
    {
        LOG_ERR << errno << " Open failed " << full_path;
        return -1;
    }

    const off_t offset = block_id * BLOCK_SIZE;
    int ret = pwrite(fd, buf, len, offset);
    close(fd);
    if (ret == -1)
    {
        LOG_ERR << errno << " Write failed " << full_path;
        return -1;
    }

    hasher::B2H hash = hasher::hash(&offset, 8, buf, len);
    touched_files[file_relpath].emplace(block_id, hash);

    return 0;
}

/**
 * Computes the latest hash tree with any changes recorded in touched files index.
 * @return 0 on success. -1 on failure.
 */
int compute_hash_tree(hasher::B2H &statehash, const bool force_all)
{
    hashtree_builder htree_builder(current_ctx);

    int ret = force_all ? htree_builder.generate(statehash, true) : htree_builder.generate(statehash, touched_files);

    touched_files.clear();
    return ret;
}

//-----Private helper functions---------//

/**
 * Reads bytes from file into a buffer.
 * @param buf Buffer to fill with the read bytes.
 * @param filepath Full path to the file.
 * @param start Starting offset to read.
 * @param len Number of bytes to read.
 * @return Number of bytes read on successful read. -1 on failure.
 */
int read_file_bytes(void *buf, const char *filepath, const off_t start, const size_t len)
{
    int fd = open(filepath, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << " Open failed " << filepath;
        return -1;
    }

    int read_bytes = pread(fd, buf, len, start);
    close(fd);
    if (read_bytes <= 0)
    {
        LOG_ERR << errno << " Read failed " << filepath;
        return -1;
    }

    return read_bytes;
}

/**
 * Reads bytes from file into a vector. The vector size will be adjusted to the actual bytes read.
 * @param vec Vector to fill with the read bytes.
 * @param filepath Full path to the file.
 * @param start Starting offset to read.
 * @return Number of bytes read on successful read. -1 on failure.
 */
int read_file_bytes_to_end(std::vector<uint8_t> &vec, const char *filepath, const off_t start)
{
    int fd = open(filepath, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << " Open failed " << filepath;
        return -1;
    }

    const off_t total_len = lseek(fd, 0, SEEK_END);
    if (total_len == -1)
        return -1;

    const size_t len = total_len - start;
    vec.resize(len);

    int read_bytes = pread(fd, vec.data(), len, start);
    close(fd);
    if (read_bytes <= 0)
    {
        LOG_ERR << errno << " Read failed " << filepath;
        return -1;
    }
    vec.resize(read_bytes);

    return read_bytes;
}

} // namespace statefs