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

/**
 * Creates a new checkpoint directory. This will remove the oldest checkpoint if we have
 * reached MAX_CHECKPOINTS. This is called whenever fuse filesystem is run so the contract
 * always runs on a new checkpoint.
 */
void state_monitor::create_checkpoint()
{
    /**
     * Checkpoints are numbered 0, -1, -2, ...
     * Checkpoint 0 is the latest state containing "state", "data", "delta", "bhmap", "htree" directories.
     * Checkpoints -1 and lower contains only the "delta" dirs containing older state changesets.
     */

    // Shift "-1" and older checkpoints by 1 more. And then copy checkpoint 0 delta dir to "-1".
    // If MAX oldest checkpoint is there, remove it and work our way upwards.
    int16_t oldest_chkpnt = MAX_CHECKPOINTS * -1;
    for (int16_t chkpnt = oldest_chkpnt; chkpnt <= -1; chkpnt++)
    {
        std::string dir = get_state_dir_root(chkpnt);

        if (boost::filesystem::exists(dir))
        {
            if (chkpnt == oldest_chkpnt)
            {
                boost::filesystem::remove_all(dir);
            }
            else
            {
                std::string dir_shift = get_state_dir_root(chkpnt - 1);
                boost::filesystem::rename(dir, dir_shift);
            }
        }

        if (chkpnt == -1)
        {
            state_dir_context ctx = get_state_dir_context(0, true);

            // Shift 0-state delta dir to -1.
            std::string delta_1 = dir + DELTA_DIR;
            boost::filesystem::create_directories(delta_1);

            boost::filesystem::rename(ctx.delta_dir, delta_1);
            boost::filesystem::create_directories(ctx.delta_dir);
        }
    }

    return;
}

/**
 * Called whenever a new file is created in the fuse fs.
 * @param fd The fd of the created file.
 */
void state_monitor::oncreate(const int fd)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    std::string filepath;
    if (extract_filepath(filepath, fd) == 0)
        oncreate_filepath(filepath);
}

/**
 * Called whenever a file is going to be opened.
 * @param inodefd inode fd given by fuse fs. This is used to find the physical path of the file.
 * @param flags Open flags.
 */
void state_monitor::onopen(const int inodefd, const int flags)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    // Find the actual file path which is going to be opened and add that path to tracked file info list.
    std::string filepath;
    if (extract_filepath(filepath, inodefd) == 0)
    {
        state_file_info *fi;
        if (get_tracked_fileinfo(&fi, filepath) == 0)
        {
            // Check whether the file is going to be opened in truncate mode.
            // If so cache the entire file immediately because this is the last chance we get to backup the data.
            if (flags & O_TRUNC)
                cache_blocks(*fi, 0, fi->original_length);
        }
    }
}

/**
 * Called whenever a file is being written to.
 * @param fd fd of the file being written to.
 * @param offset Byte offset of the write.
 * @param length Number of bytes being overwritten.
 */
void state_monitor::onwrite(const int fd, const off_t offset, const size_t length)
{
    // TODO: Known issue: onwrite can get called if the client program deletes a file before
    // closing the currently open file. If there were some bytes on the write buffer, the flush happens
    // when the client closes the fd. By that time the fd is invalid since the file is deleted.
    // However nothing happens to us as our code simply returns on invalild fd error.

    std::lock_guard<std::mutex> lock(monitor_mutex);

    // Find the actual filepath being written to and cache the blocks to server as backup.
    std::string filepath;
    if (get_fd_filepath(filepath, fd) == 0)
    {
        state_file_info *fi;
        if (get_tracked_fileinfo(&fi, filepath) == 0)
            cache_blocks(*fi, offset, length);
    }
}

/**
 * Called when a file is being renamed.
 * We simply treat this as delete-and-create operation.
 */
void state_monitor::onrename(const std::string &old_filepath, const std::string &new_filepath)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    ondelete_filepath(old_filepath);
    oncreate_filepath(new_filepath);
}

/**
 * Called when a file is being deleted.
 */
void state_monitor::ondelete(const std::string &filepath)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);
    ondelete_filepath(filepath);
}

/**
 * Called when a file is being truncated.
 */
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

/**
 * Called when an open file is being closed. Here, we clear any tracking information we kept for this file
 * and close off any related fds associated with any backup operations for this file.
 */
void state_monitor::onclose(const int fd)
{
    std::lock_guard<std::mutex> lock(monitor_mutex);

    // fd_path_map should contain this fd already if we were tracking it.

    auto pitr = fd_path_map.find(fd);
    if (pitr != fd_path_map.end())
    {
        // Close any block cache/index fds we have opened for this file.
        auto fitr = file_info_map.find(pitr->second); // pitr->second is the filepath string.
        if (fitr != file_info_map.end())
            close_caching_fds(fitr->second); // fitr->second is the fileinfo struct.

        fd_path_map.erase(pitr);
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
    const auto itr = fd_path_map.find(fd);
    if (itr != fd_path_map.end())
    {
        filepath = itr->second;
        return 0;
    }

    // Extract the file path and populate the fd-->filepath map.
    if (extract_filepath(filepath, fd) == 0)
    {
        fd_path_map[fd] = filepath;
        return 0;
    }

    return -1;
}

/**
 * Called when a new file is going to be created. fd is not yet open at this point.
 * We need to catch this and start tracking this filepath.
 */
void state_monitor::oncreate_filepath(const std::string &filepath)
{
    // Check whether we are already tracking this file path.
    // Only way we could be tracking this path already is deleting an existing file and creating
    // a new file with the same name.
    if (file_info_map.count(filepath) == 0)
    {
        // Add an entry for the new file in the file info map. This information will be used to ignore
        // future operations (eg. write/delete) done to this file.
        state_file_info fi;
        fi.is_new = true;
        fi.filepath = filepath;
        file_info_map[filepath] = std::move(fi);

        // Add to the list of new files added during this session.
        write_new_file_entry(filepath);
    }
}

/**
 * Called when a file is going to be deleted. We use this to remove any tracking information
 * regarding this file and to backup the file before deletion.
 */
void state_monitor::ondelete_filepath(const std::string &filepath)
{
    state_file_info *fi;
    if (get_tracked_fileinfo(&fi, filepath) == 0)
    {
        if (fi->is_new)
        {
            // If this is a new file, just remove from existing index entries.
            // No need to cache the file blocks.
            remove_new_file_entry(fi->filepath);
            file_info_map.erase(filepath);
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
    const auto itr = file_info_map.find(filepath);
    if (itr != file_info_map.end())
    {
        *fi = &itr->second;
        return 0;
    }

    // Initialize a new state file info struct for the given filepath.
    state_file_info &fileinfo = file_info_map[filepath];

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
 * Backs up the specified bytes range of the given file. This is called whenever a file is being
 * overwritten/deleted.
 * @param fi The file info struct pointing to the file to be cached.
 * @param offset The start byte position for caching.
 * @param length How many bytes to cache.
 * @return 0 on successful execution. -1 on failure.
 */
int state_monitor::cache_blocks(state_file_info &fi, const off_t offset, const size_t length)
{
    // No caching required if this is a new file created during this session.
    if (fi.is_new)
        return 0;

    uint32_t original_block_count = ceil((double)fi.original_length / (double)BLOCK_SIZE);

    // Check whether we have already cached the entire file.
    if (original_block_count == fi.cached_blockids.size())
        return 0;

    // Initialize fds and indexes required for caching the file.
    if (prepare_caching(fi) != 0)
        return -1;

    // Return if incoming write is outside any of the original blocks.
    if (offset > original_block_count * BLOCK_SIZE)
        return 0;

    uint32_t startblock = offset / BLOCK_SIZE;
    uint32_t endblock = (offset + length) / BLOCK_SIZE;

    // std::cout << "Cache blocks: '" << fi.filepath << "' [" << offset << "," << length << "] " << startblock << "," << endblock << "\n";

    // If this is the first time we are caching this file, write an entry to the touched file index.
    // Touched file index is used by rollback to server as a guide.
    if (fi.cached_blockids.empty() && write_touched_file_entry(fi.filepath) != 0)
        return -1;

    for (uint32_t i = startblock; i <= endblock; i++)
    {
        // Skip if we have already cached this block.
        if (fi.cached_blockids.count(i) > 0)
            continue;

        // Read the block being replaced and send to cache file.
        // Allocating block buffer on the heap to avoid filling limited stack space.
        std::unique_ptr<char[]> block_buf = std::make_unique<char[]>(BLOCK_SIZE);
        off_t block_offset = BLOCK_SIZE * i;
        size_t bytes_read = pread(fi.readfd, block_buf.get(), BLOCK_SIZE, BLOCK_SIZE * i);
        if (bytes_read < 0)
        {
            std::cerr << errno << ": Read failed " << fi.filepath << "\n";
            return -1;
        }

        // No more bytes to read in this file.
        if (bytes_read == 0)
            return 0;

        if (write(fi.cachefd, block_buf.get(), bytes_read) < 0)
        {
            std::cerr << errno << ": Write to block cache failed. " << fi.filepath << "\n";
            return -1;
        }

        // Append an entry (44 bytes) into the block cache index. We maintain this index to
        // help random block access for external use cases. We currently do not sort this index here.
        // Whoever is using the index must sort it if required.
        // Entry format: [blocknum(4 bytes) | cacheoffset(8 bytes) | blockhash(32 bytes)]

        // Calculate the block hash by combining block offset with block data.
        char entrybuf[BLOCK_INDEX_ENTRY_SIZE];
        hasher::B2H hash = hasher::hash(&block_offset, 8, block_buf.get(), bytes_read);

        // Original file block id.
        memcpy(entrybuf, &i, 4);
        // Position of the block within the cache file.
        off_t cacheoffset = fi.cached_blockids.size() * BLOCK_SIZE;
        memcpy(entrybuf + 4, &cacheoffset, 8);
        // The block hash.
        memcpy(entrybuf + 12, hash.data, 32);
        if (write(fi.indexfd, entrybuf, BLOCK_INDEX_ENTRY_SIZE) < 0)
        {
            std::cerr << errno << ": Write to block index failed. " << fi.filepath << "\n";
            return -1;
        }

        // Mark the block as cached.
        fi.cached_blockids.emplace(i);
    }

    return 0;
}

/**
 * Initializes fds and indexes required for caching a particular file.
 * @param fi The state file info struct pointing to the file being cached.
 * @return 0 on succesful initialization. -1 on failure.
 */
int state_monitor::prepare_caching(state_file_info &fi)
{
    // If readfd is greater than 0 then we take it as caching being already initialized for this file.
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
    std::string relpath = get_relpath(fi.filepath, ctx.data_dir);

    std::string tmppath;
    tmppath.reserve(ctx.delta_dir.length() + relpath.length() + BLOCK_CACHE_EXT_LEN);
    tmppath.append(ctx.delta_dir).append(relpath).append(BLOCK_CACHE_EXT);

    // Create directory tree if not exist so we are able to create the cache and index files.
    boost::filesystem::path cachesubdir = boost::filesystem::path(tmppath).parent_path();
    if (created_cache_subdirs.count(cachesubdir.string()) == 0)
    {
        boost::filesystem::create_directories(cachesubdir);
        created_cache_subdirs.emplace(cachesubdir.string());
    }

    // Create and open the block cache file.
    fi.cachefd = open(tmppath.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
    if (fi.cachefd <= 0)
    {
        std::cerr << errno << ": Open failed " << tmppath << "\n";
        return -1;
    }

    // Create and open the block index file.
    tmppath.replace(tmppath.length() - BLOCK_CACHE_EXT_LEN, BLOCK_INDEX_EXT_LEN, BLOCK_INDEX_EXT);
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
void state_monitor::close_caching_fds(state_file_info &fi)
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
 * This index is used to restore modified files during rollback.
 */
int state_monitor::write_touched_file_entry(std::string_view filepath)
{
    if (touched_fileindex_fd <= 0)
    {
        std::string index_file = ctx.delta_dir + IDX_TOUCHED_FILES;
        touched_fileindex_fd = open(index_file.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
        if (touched_fileindex_fd <= 0)
        {
            std::cerr << errno << ": Open failed " << index_file << "\n";
            return -1;
        }
    }

    // Write the relative file path line to the index.
    filepath = filepath.substr(ctx.data_dir.length(), filepath.length() - ctx.data_dir.length());
    write(touched_fileindex_fd, filepath.data(), filepath.length());
    write(touched_fileindex_fd, "\n", 1);
    return 0;
}

/**
 * Inserts a file into the list of new files created during this session.
 * This index is used in deleting new files during restore.
 */
int state_monitor::write_new_file_entry(std::string_view filepath)
{
    std::string index_file = ctx.delta_dir + IDX_NEW_FILES;
    int fd = open(index_file.c_str(), O_WRONLY | O_APPEND | O_CREAT, FILE_PERMS);
    if (fd <= 0)
    {
        std::cerr << errno << ": Open failed " << index_file << "\n";
        return -1;
    }

    // Write the relative file path line to the index.
    filepath = filepath.substr(ctx.data_dir.length(), filepath.length() - ctx.data_dir.length());
    write(fd, filepath.data(), filepath.length());
    write(fd, "\n", 1);
    close(fd);
    return 0;
}

/**
 * Scans and removes the given filepath from the new files index.
 * This is called when a file added during this session gets deleted in the same session.
 */
void state_monitor::remove_new_file_entry(std::string_view filepath)
{
    filepath = filepath.substr(ctx.data_dir.length(), filepath.length() - ctx.data_dir.length());

    // We create a copy of the new file index and transfer lines from first file
    // to the second file except the line matching the given filepath.

    std::string index_file = ctx.delta_dir + IDX_NEW_FILES;
    std::string index_file_tmp = ctx.delta_dir + IDX_NEW_FILES + ".tmp";

    std::ifstream in_file(index_file);
    std::ofstream outfile(index_file_tmp);

    bool lines_transferred = false;
    for (std::string line; std::getline(in_file, line);)
    {
        if (line != filepath) // Skip the file being removed.
        {
            outfile << line << "\n";
            lines_transferred = true;
        }
    }

    in_file.close();
    outfile.close();

    // Remove the old index.
    std::remove(index_file.c_str());

    // If no lines transferred, delete the temp file as well.
    if (lines_transferred)
        std::rename(index_file_tmp.c_str(), index_file.c_str());
    else
        std::remove(index_file_tmp.c_str());
}

} // namespace statefs