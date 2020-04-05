#ifndef _HP_UTIL_
#define _HP_UTIL_

#include "pchheader.hpp"
#include "crypto.hpp"

/**
 * Contains helper functions and data structures used by multiple other subsystems.
 */
namespace util
{

// Hot Pocket version. Displayed on 'hotpocket version' and written to new contract configs.
constexpr const char *HP_VERSION = "0.1";

// Minimum compatible contract config version (this will be used to validate contract configs)
constexpr const char *MIN_CONTRACT_VERSION = "0.1";

// Current version of the peer message protocol.
constexpr uint8_t PEERMSG_VERSION = 1;

// Minimum compatible peer message version (this will be used to accept/reject incoming peer connections)
// (Keeping this as int for effcient msg payload and comparison)
constexpr uint8_t MIN_PEERMSG_VERSION = 1;

// Minimum compatible npl contract input version (this will be used to generate the npl input to feed the contract)
// (Keeping this as int for effcient msg payload and comparison)
constexpr uint8_t MIN_NPL_INPUT_VERSION = 1;



/**
 * FIFO hash set with a max size.
 */
class rollover_hashset
{
private:
    // The set of recent hashes used for duplicate detection.
    std::unordered_set<std::string> recent_hashes;

    // The supporting list of recent hashes used for adding and removing hashes from
    // the 'recent_hashes' in a first-in-first-out manner.
    std::list<const std::string *> recent_hashes_list;

    uint32_t maxsize;

public:
    rollover_hashset(const uint32_t maxsize);
    bool try_emplace(const std::string hash);
};

/**
 * A string set with expiration for elements.
 */
class ttl_set
{
private:
    // Keeps short-lived items with their absolute expiration time.
    std::unordered_map<std::string, uint64_t> ttlmap;

public:
    void emplace(const std::string key, uint64_t ttl_milli);
    void erase(const std::string &key);
    bool exists(const std::string &key);
};

int bin2hex(std::string &encoded_string, const unsigned char *bin, const size_t bin_len);

int hex2bin(unsigned char *decoded, const size_t decoded_len, std::string_view hex_str);

int64_t get_epoch_milliseconds();

void sleep(const uint64_t milliseconds);

int version_compare(const std::string &x, const std::string &y);

std::string_view getsv(const rapidjson::Value &v);

std::string realpath(std::string path);

void mask_signal();

} // namespace util

#endif
