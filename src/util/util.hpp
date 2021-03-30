#ifndef _HP_UTIL_UTIL_
#define _HP_UTIL_UTIL_

#include "../pchheader.hpp"

/**
 * Contains helper functions and data structures used by multiple other subsystems.
 */

#define MAX(a, b) ((a > b) ? a : b)
#define MIN(a, b) ((a < b) ? a : b)

namespace util
{
    /**
     * The messaging protocol used in a web socket channel.
     */
    enum PROTOCOL
    {
        JSON = 0,
        BSON = 1
    };

    const std::string to_hex(const std::string_view bin);

    const std::string to_bin(const std::string_view hex);

    uint64_t get_epoch_milliseconds();

    void sleep(const uint64_t milliseconds);

    const std::string realpath(const std::string &path);

    void mask_signal();

    void fork_detach();

    int kill_process(const pid_t pid, const bool wait, const int signal = SIGINT);

    bool is_dir_exists(std::string_view path);

    bool is_file_exists(std::string_view path);

    int create_dir_tree_recursive(std::string_view path);

    std::list<std::string> fetch_dir_entries(std::string_view path);

    std::string_view fetch_file_extension(std::string_view path);

    std::string_view remove_file_extension(std::string_view file_name);

    int remove_file(std::string_view path);

    int clear_directory(std::string_view dir_path);

    int remove_directory_recursively(std::string_view dir_path);

    void split_string(std::vector<std::string> &collection, std::string_view str, std::string_view delimeter);

    int stoull(const std::string &str, uint64_t &result);

    const std::string get_name(std::string_view path);

    int read_from_fd(const int fd, std::string &buf, const off_t offset = 0);

    int set_lock(const int fd, struct flock &lock, const bool is_rwlock, const off_t start, const off_t len);

    int release_lock(const int fd, struct flock &lock);

    void uint16_to_bytes(uint8_t *dest, const uint16_t x);

    uint16_t uint16_from_bytes(const uint8_t *data);

    void uint32_to_bytes(uint8_t *dest, const uint32_t x);

    uint32_t uint32_from_bytes(const uint8_t *data);

    void uint64_to_bytes(uint8_t *dest, const uint64_t x);

    uint64_t uint64_from_bytes(const uint8_t *data);

} // namespace util

#endif
