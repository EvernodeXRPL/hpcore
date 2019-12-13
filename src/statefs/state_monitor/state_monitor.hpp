#ifndef _HP_STATEFS_STATE_MONITOR_
#define _HP_STATEFS_STATE_MONITOR_

#include <cstdint>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <boost/filesystem.hpp>
#include "../state_common.hpp"

namespace statefs
{

/**
 * Holds information about an original file in state that we are tracking.
 */
struct state_file_info
{
    bool is_new;            // Whether this is a new file created during this session.
    off_t original_length;  // Original file length.
    std::unordered_set<uint32_t> cached_blockids;   // Set of block ids cached during this session.
    std::string filepath;   // Actual real path of the file. (not fuse path)
    int readfd;             // fd used for reading the original file for caching.
    int cachefd;            // fd for writing into the block cache file.
    int indexfd;            // fd for writing into the block index file.
};

/**
 * Invoked by fuse file system for relevent file system calls.
 */
class state_monitor
{
private:
    // Map of fd-->filepath
    std::unordered_map<int, std::string> fd_path_map;

    // Map of filepath-->fileinfo
    std::unordered_map<std::string, state_file_info> file_info_map;

    // List of new cache sub directories created during the session.
    std::unordered_set<std::string> created_cache_subdirs;

    // Mutex to synchronize parallel file system calls into our custom state tracking logic.
    std::mutex monitor_mutex;

    // Holds the fd used to write into modified files index. This will be kept open for the entire
    // life of the state monitor.
    int touched_fileindex_fd = 0;

    int extract_filepath(std::string &filepath, const int fd);
    int get_fd_filepath(std::string &filepath, const int fd);
    void oncreate_filepath(const std::string &filepath);
    void ondelete_filepath(const std::string &filepath);
    int get_tracked_fileinfo(state_file_info **fileinfo, const std::string &filepath);

    int cache_blocks(state_file_info &fi, const off_t offset, const size_t length);
    int prepare_caching(state_file_info &fi);
    void close_caching_fds(state_file_info &fi);
    int write_touched_file_entry(std::string_view filepath);
    int write_new_file_entry(std::string_view filepath);
    void remove_new_file_entry(std::string_view filepath);

public:
    statedir_context ctx;
    void create_checkpoint();
    void oncreate(const int fd);
    void onopen(const int inodefd, const int flags);
    void onwrite(const int fd, const off_t offset, const size_t length);
    void onrename(const std::string &old_filepath, const std::string &new_filepath);
    void ondelete(const std::string &filepath);
    void ontruncate(const int fd, const off_t newsize);
    void onclose(const int fd);
};

} // namespace statefs

#endif