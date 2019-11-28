#include "../pchheader.hpp"
#include "hasher.hpp"
#include "state_common.hpp"
#include "../hplog.hpp"

namespace statefs
{
struct fs_hash_entry
{
    bool isfile;
    std::string path;
    hasher::B2H hash;
};

struct block_hash_entry
{
    uint32_t blockid;
    hasher::B2H hash;
};

// Map of modified/deleted files with updated blockids and hashes (if modified)
std::unordered_map<std::string, std::map<uint32_t, hasher::B2H>> touchedfiles;

int read_file_bytes(void *buf, const char *bhmapfile, const off_t start, const size_t len)
{
    int fd = open(bhmapfile, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << bhmapfile;
        return -1;
    }

    int readbytes = pread(fd, buf, len, start);
    close(fd);
    if (readbytes <= 0)
    {
        LOG_ERR << errno << "Read failed " << bhmapfile;
        return -1;
    }

    return readbytes;
}

int read_file_bytes(std::vector<uint8_t> &vec, const char *bhmapfile, const off_t start)
{
    int fd = open(bhmapfile, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERR << errno << "Open failed " << bhmapfile;
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
        LOG_ERR << errno << "Read failed " << bhmapfile;
        return -1;
    }
    vec.resize(readbytes);

    return readbytes;
}

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

int get_block_hashes(std::vector<uint8_t> &vec, const std::string &filerelpath)
{
    const std::string bhmap_path = current_ctx.hashtreedir + "/" + filerelpath + HASHMAP_EXT;

    if (read_file_bytes(vec, bhmap_path.c_str(), hasher::HASH_SIZE) == -1)
        return -1;

    return 0;
}

int delete_folder(const std::string &dirrelpath)
{
    std::string fullpath = current_ctx.datadir + "/" + dirrelpath;
    if (boost::filesystem::remove_all(fullpath) == -1)
        return -1;

    std::string hintpath = dirrelpath + "/.";
    touchedfiles.emplace(std::move(hintpath), std::map<uint32_t, hasher::B2H>());
    return 0;
}

int delete_file(const std::string &filerelpath)
{
    std::string fullpath = current_ctx.datadir + "/" + filerelpath;
    if (boost::filesystem::remove(fullpath) == -1)
        return -1;

    touchedfiles.emplace(filerelpath, std::map<uint32_t, hasher::B2H>());
    return 0;
}

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

} // namespace statefs