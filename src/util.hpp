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
static const char *HP_VERSION = "0.1";

// Minimum compatible contract config version (this will be used to validate contract configs)
static const char *MIN_CONTRACT_VERSION = "0.1";

// Current version of the peer message protocol.
static const int PEERMSG_VERSION = 1;

// Minimum compatible peer message version (this will be used to accept/reject incoming peer connections)
// (Keeping this as int for effcient msg payload and comparison)
static const int MIN_PEERMSG_VERSION = 1;

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
    rollover_hashset(uint32_t maxsize);
    bool try_emplace(std::string hash);
};

int bin2hex(std::string &encoded_string, const unsigned char *bin, size_t bin_len);

int hex2bin(unsigned char *decoded, size_t decoded_len, std::string_view hex_str);

int64_t get_epoch_milliseconds();

void sleep(uint64_t milliseconds);

int version_compare(const std::string &x, const std::string &y);

std::string_view getsv(const rapidjson::Value &v);

} // namespace util

#endif