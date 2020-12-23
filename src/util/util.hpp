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
    // Hot Pocket version. Displayed on 'hotpocket version' and written to new contract configs.
    constexpr const char *HP_VERSION = "0.1";

    // Minimum compatible config version (this will be used to validate contract configs)
    constexpr const char *MIN_CONFIG_VERSION = "0.1";

    // Current version of the peer message protocol.
    constexpr uint8_t PEERMSG_VERSION = 1;

    // Minimum compatible peer message version (this will be used to accept/reject incoming peer connections)
    // (Keeping this as int for effcient msg payload and comparison)
    constexpr uint8_t MIN_PEERMSG_VERSION = 1;

    // Minimum compatible npl contract input version (this will be used to generate the npl input to feed the contract)
    // (Keeping this as int for effcient msg payload and comparison)
    constexpr uint8_t MIN_NPL_INPUT_VERSION = 1;

    /**
     * The messaging protocol used in a web socket channel.
     */
    enum PROTOCOL
    {
        JSON = 0,
        BSON = 1
    };

    const std::string to_hex(const std::string_view bin);

    int hex2bin(unsigned char *decoded, const size_t decoded_len, std::string_view hex_str);

    uint64_t get_epoch_milliseconds();

    void sleep(const uint64_t milliseconds);

    int version_compare(const std::string &x, const std::string &y);

    std::string realpath(const std::string &path);

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

} // namespace util

#endif
