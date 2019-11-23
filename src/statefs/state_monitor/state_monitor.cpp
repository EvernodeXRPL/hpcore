#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unordered_map>
#include <cmath>
#include <boost/filesystem.hpp>
#include <fstream>
#include <sstream>
#include <string>
#include <errno.h>
#include "../hasher.hpp"
#include "../state_common.hpp"
#include "state_monitor.hpp"

namespace statefs
{

void state_monitor::create_checkpoint()
{
    // Shift -1 and below checkpoints by 1 more.
    // If MAX oldest checkpoint is there, remove it and work our way upwards.
    int16_t oldest_chkpnt = (MAX_CHECKPOINTS + 1) * -1; // +1 because we maintain one extra checkpoint in case of rollbacks.
    for (int16_t chkpnt = oldest_chkpnt; chkpnt <= -1; chkpnt++)
    {
        std::string dir = get_statedir_root(chkpnt);

        if (boost::filesystem::exists(dir))
        {
            if (chkpnt == oldest_chkpnt)
            {
                boost::filesystem::remove_all(dir);
            }
            else
            {
                std::string dirshift = get_statedir_root(chkpnt - 1);
                boost::filesystem::rename(dir, dirshift);
            }
        }

        if (chkpnt == -1)
        {
            statedir_context ctx = get_statedir_context(0, true);

            // Shift 0-state delta dir to -1.
            std::string delta_1 = dir + DELTA_DIR;
            boost::filesystem::create_directories(delta_1);

            boost::filesystem::rename(ctx.deltadir, delta_1);
            boost::filesystem::create_directories(ctx.deltadir);
        }
    }

    return;
}

void state_monitor::oncreate(const int fd)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    std::string filepath;
    if (extract_filepath(filepath, fd) == 0)
        oncreate_filepath(filepath);
}

void state_monitor::onopen(const int inodefd, const int flags)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    std::string filepath;
    if (extract_filepath(filepath, inodefd) == 0)
    {
        state_file_info *fi;
        if (get_tracked_fileinfo(&fi, filepath) == 0)
        {
            // Check whether fd is open in truncate mode. If so cache the entire file immediately.
            if (flags & O_TRUNC)
                cache_blocks(*fi, 0, fi->original_length);
        }
    }
}

void state_monitor::onwrite(const int fd, const off_t offset, const size_t length)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    std::string filepath;
    if (get_fd_filepath(filepath, fd) == 0)
    {
        state_file_info *fi;
        if (get_tracked_fileinfo(&fi, filepath) == 0)
            cache_blocks(*fi, offset, length);
    }
}

void state_monitor::onrename(const std::string &oldfilepath, const std::string &newfilepath)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    ondelete_filepath(oldfilepath);
    oncreate_filepath(newfilepath);
}

void state_monitor::ondelete(const std::string &filepath)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);
    ondelete_filepath(filepath);
}

void state_monitor::ontruncate(const int fd, const off_t newsize)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    std::string filepath;
    if (get_fd_filepath(filepath, fd) == 0)
    {
        // If truncated size is less than the original, cache the entire file.
        state_file_info *fi;
        if (get_tracked_fileinfo(&fi, filepath) == 0 && newsize < fi->original_length)
            cache_blocks(*fi, 0, fi->original_length);
    }
}

void state_monitor::onclose(const int fd)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    auto pitr = fdpathmap.find(fd);
    if (pitr != fdpathmap.end())
    {
        // Close any block cache/index fds we have opened for this file.
        auto fitr = fileinfomap.find(pitr->second); // pitr->second is the filepath string.
        if (fitr != fileinfomap.end())
            close_cachingfds(fitr->second); // fitr->second is the fileinfo struct.

        fdpathmap.erase(pitr);
    }
}

/**
 * Extracts the full physical file path for a given fd.
 * @param filepath String to assign the extracted file path.
 * @param fd The file descriptor to find the filepath.
 * @return 0 on successful file path extraction. -1 on failure.
 */
int state_monitor::extract_filepath(std::string &filepath, const int fd)
{
    char proclnk[32];
    sprintf(proclnk, "/proc/self/fd/%d", fd);

    filepath.resize(PATH_MAX);
    ssize_t len = readlink(proclnk, filepath.data(), PATH_MAX);
    if (len > 0)
    {
        filepath.resize(len);
        return 0;
    }
    return -1;
}

/**
 * Find the full physical file path for a given fd using the fd map.
 * @param filepath String to assign the extracted file path.
 * @param fd The file descriptor to find the filepath.
 * @return 0 on successful file path extraction. -1 on failure.
 */
int state_monitor::get_fd_filepath(std::string &filepath, const int fd)
{
    // Return path from the map if found.
    const auto itr = fdpathmap.find(fd);
    if (itr != fdpathmap.end())
    {
        filepath = itr->second;
        return 0;
    }

    // Extract the file path and populate the fd-->filepath map.
    if (extract_filepath(filepath, fd) == 0)
    {
        fdpathmap[fd] = filepath;
        return 0;
    }

    return -1;
}

void state_monitor::oncreate_filepath(const std::string &filepath)
{
    // Check whether we are already tracking this file path.
    // Only way this could happen is deleting an existing file and creating a new file with same name.
    if (fileinfomap.count(filepath) == 0)
    {
        // Add an entry for the new file in the file info map. This information will be used to ignore
        // future operations (eg. write/delete) done to this file.
        state_file_info fi;
        fi.isnew = true;
        fi.filepath = filepath;
        fileinfomap[filepath] = std::move(fi);

        // Add to the list of new files added during this session.
        write_newfileentry(filepath);
    }
}

void state_monitor::ondelete_filepath(const std::string &filepath)
{
    state_file_info *fi;
    if (get_tracked_fileinfo(&fi, filepath) == 0)
    {
        if (fi->isnew)
        {
            // If this is a new file, just remove from existing index entries.
            // No need to cache the file blocks.
            remove_newfileentry(fi->filepath);
            fileinfomap.erase(filepath);
        }
        else
        {
            // If not a new file, cache the entire file.
            cache_blocks(*fi, 0, fi->original_length);
        }
    }
}

/**
 * Finds the tracked state file information for the given filepath.
 * @param fi Reference pointer to assign the state file info struct.
 * @param filepath Full physical path of the file.
 * @return 0 on successful find. -1 on failure.
 */
int state_monitor::get_tracked_fileinfo(state_file_info **fi, const std::string &filepath)
{
    // Return from filepath-->fileinfo map if found.
    const auto itr = fileinfomap.find(filepath);
    if (itr != fileinfomap.end())
    {
        *fi = &itr->second;
        return 0;
    }

    // Initialize a new state file info struct for the given filepath.
    state_file_info &fileinfo = fileinfomap[filepath];

    // We use stat() to find out the length of the file.
    struct stat stat_buf;
    if (stat(filepath.c_str(), &stat_buf) != 0)
    {
        std::cerr << errno << ": Error occured in stat() of " << filepath << "\n";
        return -1;
    }

    fileinfo.original_length = stat_buf.st_size;
    fileinfo.filepath = filepath;
    *fi = &fileinfo;
    return 0;
}

/**
 * Caches the specified bytes range of the given file.
 * @param fi The file info struct pointing to the file to be cached.
 * @param offset The start byte position for caching.
 * @param length How many bytes to cache.
 * @return 0 on successful execution. -1 on failure.
 */
int state_monitor::cache_blocks(state_file_info &fi, const off_t offset, const size_t length)
{
    // No caching required if this is a new file created during this session.
    if (fi.isnew)
        return 0;

    uint32_t original_blockcount = ceil((double)fi.original_length / (double)BLOCK_SIZE);

    // Check whether we have already cached the entire file.
    if (original_blockcount == fi.cached_blockids.size())
        return 0;

    // Initialize fds and indexes required for caching.
    if (prepare_caching(fi) != 0)
        return -1;

    // Return if incoming write is outside any of the original blocks.
    if (offset > original_blockcount * BLOCK_SIZE)
        return 0;

    uint32_t startblock = offset / BLOCK_SIZE;
    uint32_t endblock = (offset + length) / BLOCK_SIZE;

    // std::cout << "Cache blocks: '" << fi.filepath << "' [" << offset << "," << length << "] " << startblock << "," << endblock << "\n";

    // If this is the first time we are caching this file, write an entry to the touched file index.
    if (fi.cached_blockids.empty() && write_touchedfileentry(fi.filepath) != 0)
        return -1;

    for (uint32_t i = startblock; i <= endblock; i++)
    {
        // Skip if we have already cached this block.
        if (fi.cached_blockids.count(i) > 0)
            continue;

        // Read the block being replaced and send to cache file.
        char blockbuf[BLOCK_SIZE];
        off_t blockoffset = BLOCK_SIZE * i;
        if (pread(fi.readfd, blockbuf, BLOCK_SIZE, BLOCK_SIZE * i) < 0)
        {
            std::cerr << errno << ": Read failed " << fi.filepath << "\n";
            return -1;
        }

        if (write(fi.cachefd, blockbuf, BLOCK_SIZE) < 0)
        {
            std::cerr << errno << ": Write to block cache failed\n";
            return -1;
        }

        // Append an entry (44 bytes) into the block cache index. We maintain this index to
        // help random block access for external use cases. We currently do not sort this index here.
        // Whoever is using the index must sort it if required.
        // Entry format: [blocknum(4 bytes) | cacheoffset(8 bytes) | blockhash(32 bytes)]

        char entrybuf[BLOCKINDEX_ENTRY_SIZE];
        off_t cacheoffset = fi.cached_blockids.size() * BLOCK_SIZE;
        hasher::B2H hash = hasher::hash(&blockoffset, 8, blockbuf, BLOCK_SIZE);

        memcpy(entrybuf, &i, 4);
        memcpy(entrybuf + 4, &cacheoffset, 8);
        memcpy(entrybuf + 12, hash.data, 32);
        if (write(fi.indexfd, entrybuf, BLOCKINDEX_ENTRY_SIZE) < 0)
        {
            std::cerr << errno << ": Write to block index failed\n";
            return -1;
        }

        // Mark the block as cached.
        fi.cached_blockids.emplace(i);
    }

    return 0;
}

/**
 * Initializes fds and indexes required for caching.
 * @param fi The state file info struct pointing to the file being cached.
 * @return 0 on succesful initialization. -1 on failure.
 */
int state_monitor::prepare_caching(state_file_info &fi)
{
    // If readfd is greater than 0 then we take it as caching being already initialized.
    if (fi.readfd > 0)
        return 0;

    // Open up the file using a read-only fd. This fd will be used to fetch blocks to be cached.
    fi.readfd = open(fi.filepath.c_str(), O_RDONLY);
    if (fi.readfd < 0)
    {
        std::cerr << errno << ": Open failed " << fi.filepath << "\n";
        return -1;
    }

    // Get the path of the file relative to the state dir. We maintain this same reative path for the
    // corresponding cache and index files in the cache dir.
    std::string relpath = get_relpath(fi.filepath, ctx.datadir);

    std::string tmppath;
    tmppath.reserve(ctx.deltadir.length() + relpath.length() + BLOCKCACHE_EXT_LEN);
    tmppath.append(ctx.deltadir).append(relpath).append(BLOCKCACHE_EXT);

    // Create directory tree if not exist so we are able to create the cache and index files.
    boost::filesystem::path cachesubdir = boost::filesystem::path(tmppath).parent_path();
    if (created_cachesubdirs.count(cachesubdir.string()) == 0)
    {
        boost::filesystem::create_directories(cachesubdir);
        created_cachesubdirs.emplace(cachesubdir.string());
    }

    // Create and open the block cache file.
    fi.cachefd = open(tmppath.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
    if (fi.cachefd <= 0)
    {
        std::cerr << errno << ": Open failed " << tmppath << "\n";
        return -1;
    }

    // Create and open the block index file.
    tmppath.replace(tmppath.length() - BLOCKCACHE_EXT_LEN, BLOCKINDEX_EXT_LEN, BLOCKINDEX_EXT);
    fi.indexfd = open(tmppath.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
    if (fi.indexfd <= 0)
    {
        std::cerr << errno << ": Open failed " << tmppath << "\n";
        return -1;
    }

    // Write first entry (8 bytes) to the index file. First entry is the length of the original file.
    // This will be helpful when restoring/rolling back a file.
    if (write(fi.indexfd, &fi.original_length, 8) == -1)
    {
        std::cerr << errno << ": Error writing to index file " << tmppath << "\n";
        return -1;
    }

    return 0;
}

/**
 * Closes any open caching fds for a given file.
 */
void state_monitor::close_cachingfds(state_file_info &fi)
{
    if (fi.readfd > 0)
        close(fi.readfd);

    if (fi.cachefd > 0)
        close(fi.cachefd);

    if (fi.indexfd > 0)
        close(fi.indexfd);

    fi.readfd = 0;
    fi.cachefd = 0;
    fi.indexfd = 0;
}

/**
 * Inserts a file into the modified files list of this session.
 * This index is used to restore modified files during restore.
 */
int state_monitor::write_touchedfileentry(std::string_view filepath)
{
    if (touchedfileindexfd <= 0)
    {
        std::string indexfile = ctx.deltadir + "/idxtouched.idx";
        touchedfileindexfd = open(indexfile.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
        if (touchedfileindexfd <= 0)
        {
            std::cerr << errno << ": Open failed " << indexfile << "\n";
            return -1;
        }
    }

    // Write the relative file path line to the index.
    filepath = filepath.substr(ctx.datadir.length(), filepath.length() - ctx.datadir.length());
    write(touchedfileindexfd, filepath.data(), filepath.length());
    write(touchedfileindexfd, "\n", 1);
    return 0;
}

/**
 * Inserts a file into the list of new files created during this session.
 * This index is used in deleting new files during restore.
 */
int state_monitor::write_newfileentry(std::string_view filepath)
{
    std::string indexfile = ctx.deltadir + "/idxnew.idx";
    int fd = open(indexfile.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
    if (fd <= 0)
    {
        std::cerr << errno << ": Open failed " << indexfile << "\n";
        return -1;
    }

    // Write the relative file path line to the index.
    filepath = filepath.substr(ctx.datadir.length(), filepath.length() - ctx.datadir.length());
    write(fd, filepath.data(), filepath.length());
    write(fd, "\n", 1);
    close(fd);
    return 0;
}

/**
 * Scans and removes the given filepath from the new files index.
 */
void state_monitor::remove_newfileentry(std::string_view filepath)
{
    filepath = filepath.substr(ctx.datadir.length(), filepath.length() - ctx.datadir.length());

    // We create a copy of the new file index and transfer lines from first file
    // to the second file except the line matching the given filepath.

    std::string indexfile = ctx.deltadir + "/idxnew.idx";
    std::string indexfile_tmp = ctx.deltadir + "/idxnew.idx.tmp";

    std::ifstream infile(indexfile);
    std::ofstream outfile(indexfile_tmp);

    bool linestransferred = false;
    for (std::string line; std::getline(infile, line);)
    {
        if (line != filepath) // Skip the file being removed.
        {
            outfile << line << "\n";
            linestransferred = true;
        }
    }

    infile.close();
    outfile.close();

    // Remove the old index.
    std::remove(indexfile.c_str());

    // If no lines transferred, delete the temp file as well.
    if (linestransferred)
        std::rename(indexfile_tmp.c_str(), indexfile.c_str());
    else
        std::remove(indexfile_tmp.c_str());
}

} // namespace statefs