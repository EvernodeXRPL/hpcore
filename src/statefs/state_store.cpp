#include "../pchheader.hpp"
#include "hasher.hpp"
#include "state_common.hpp"
#include "hashtree_builder.hpp"
#include "state_store.hpp"
#include "../hplog.hpp"

namespace statefs
{

// Should be replaced with flatbuffer.
struct fs_hash_entry
{
    bool isfile;
    std::string path;
    hasher::B2H hash;
};

// Map of modified/deleted files with updated blockids and hashes (if modified).
extern std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touchedfiles;

/**
 * Retrieves the hash list of the file system entries at a given directory.
 * @return 0 on success. -1 on failure.
 */
int get_fsentry_hashes(std::vector<fs_hash_entry> &hashlist, const std::string &dirrelpath)
{
    const std::string fullpath = current_ctx.datadir + "/" + dirrelpath;
    for (const boost::filesystem::directory_entry &dentry : boost::filesystem::directory_iterator(fullpath))
    {
        const boost::filesystem::path p = dentry.path();
        fs_hash_entry hashentry;
        hashentry.path = dirrelpath + "/" + p.filename().string();
        hashentry.isfile == !boost::filesystem::is_directory(p);

        // Read the first 32 bytes of the .bhmap file or dir.hash file.

        std::string hashmap_path;

        if (hashentry.isfile)
        {
            hashmap_path = hashentry.path + HASHMAP_EXT;
        }
        else
        {
            hashmap_path = hashentry.path + "/" + DIRHASH_FNAME;
            // Skip the directory if it doesn't contain the dir.hash file.
            // By that we assume the directory is empty so we're not interested in it.
            if (!boost::filesystem::exists(hashmap_path))
                continue;
        }

        if (read_file_bytes(&hashentry.hash, hashmap_path.c_str(), 0, hasher::HASH_SIZE) == -1)
            return -1;
        hashlist.push_back(std::move(hashentry));
    }
    return 0;
}

/**
 * Retrieves the block hash map for a file.
 * @return 0 on success. -1 on failure.
 */
int get_blockhashmap(std::vector<uint8_t> &vec, const std::string &filerelpath)
{
    const std::string bhmap_path = current_ctx.hashtreedir + "/" + filerelpath + HASHMAP_EXT;

    if (read_file_bytes_toend(vec, bhmap_path.c_str(), 0) == -1)
        return -1;

    return 0;
}

int get_filelength(const std::string &filerelpath)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    int fd = open(fullpath.c_str(), O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << fullpath;
        return -1;
    }

    const off_t totallen = lseek(fd, 0, SEEK_END);
    close(fd);

    return totallen;
}

/**
 * Retrieves the specified data block from a state file.
 * @return Number of bytes read on success. -1 on failure.
 */
int get_block(std::vector<uint8_t> &vec, const std::string &filerelpath, const uint32_t blockid)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    vec.resize(BLOCK_SIZE);
    int readbytes = read_file_bytes(vec.data(), fullpath.c_str(), blockid * BLOCK_SIZE, BLOCK_SIZE);
    vec.resize(readbytes);
    return readbytes;
}

/**
 * Deletes the specified state sub directory and marks the change.
 * @return 0 on success. -1 on failure.
 */
int delete_folder(const std::string &dirrelpath)
{
    std::string fullpath = current_ctx.datadir + "/" + dirrelpath;
    if (boost::filesystem::remove_all(fullpath) == -1)
        return -1;

    std::string hintpath = dirrelpath + "/.";
    touchedfiles.emplace(std::move(hintpath), std::map<uint32_t, hasher::B2H>());
    return 0;
}

/**
 * Deletes the specified state file and marks the change.
 * @return 0 on success. -1 on failure.
 */
int delete_file(const std::string &filerelpath)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    if (boost::filesystem::remove(fullpath) == -1)
        return -1;

    touchedfiles.emplace(filerelpath, std::map<uint32_t, hasher::B2H>());
    return 0;
}

/**
 * Truncates the specified state file to the specified length and marks the change.
 * @return 0 on success. -1 on failure.
 */
int truncate_file(const std::string &filerelpath, const size_t newsize)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    int fd = open(fullpath.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << fullpath;
        return -1;
    }

    int ret = ftruncate(fd, newsize);
    close(fd);
    if (ret == -1)
    {
        LOG_ERR << errno << "Truncate failed " << fullpath;
        return -1;
    }

    return 0;
}

/**
 * Writes the specified block to a file and marks the change.
 * @param filerelpath State data relative path of the file.
 * @param blockid Block id to replace/write.
 * @param buf The buffer containing data to be written.
 * @param len Length of the buffer.
 * @return 0 on success. -1 on failure.
 */
int write_block(const std::string &filerelpath, const uint32_t blockid, const void *buf, const size_t len)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    int fd = open(fullpath.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << fullpath;
        return -1;
    }

    const off_t offset = blockid * BLOCK_SIZE;
    int ret = pwrite(fd, buf, len, offset);
    close(fd);
    if (ret == -1)
    {
        LOG_ERR << errno << "Write failed " << fullpath;
        return -1;
    }

    hasher::B2H hash = hasher::hash(&offset, 8, buf, len);
    touchedfiles[filerelpath].emplace(blockid, hash);
    return 0;
}

/**
 * Computes the latest hash tree with any changes recorded in touched files index.
 * @return 0 on success. -1 on failure.
 */
int compute_hashtree()
{
    hashtree_builder htreebuilder(current_ctx);

    hasher::B2H statehash = {0, 0, 0, 0};
    int ret = htreebuilder.generate(statehash, touchedfiles);

    touchedfiles.clear();
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
        LOG_ERR << errno << "Open failed " << filepath;
        return -1;
    }

    int readbytes = pread(fd, buf, len, start);
    close(fd);
    if (readbytes <= 0)
    {
        LOG_ERR << errno << "Read failed " << filepath;
        return -1;
    }

    return readbytes;
}

/**
 * Reads bytes from file into a vector. The vector size will be adjusted to the actual bytes read.
 * @param vec Vector to fill with the read bytes.
 * @param filepath Full path to the file.
 * @param start Starting offset to read.
 * @return Number of bytes read on successful read. -1 on failure.
 */
int read_file_bytes_toend(std::vector<uint8_t> &vec, const char *filepath, const off_t start)
{
    int fd = open(filepath, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << filepath;
        return -1;
    }

    const off_t totallen = lseek(fd, 0, SEEK_END);
    if (totallen == -1)
        return -1;

    const size_t len = totallen - start;
    vec.resize(len);

    int readbytes = pread(fd, vec.data(), len, start);
    close(fd);
    if (readbytes <= 0)
    {
        LOG_ERR << errno << "Read failed " << filepath;
        return -1;
    }
    vec.resize(readbytes);

    return readbytes;
}

} // namespace statefs