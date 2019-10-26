#ifndef _HP_UTIL_H_
#define _HP_UTIL_H_

#include <string>
#include <vector>
#include <rapidjson/document.h>

/**
 * Contains helper functions and data structures used by multiple other subsystems.
 */
namespace util
{

// Hot Pocket version. Displayed on 'hotpocket version' and written to new contract configs.
static const char *HP_VERSION = "0.1";

// Current version of the peer message protocol.
static const int PEERMSG_VERSION = 1;

// Minimum compatible contract config version (this will be used to validate contract configs)
static const char *MIN_CONTRACT_VERSION = "0.1";

// Minimum compatible peer message version (this will be used to accept/reject incoming peer connections)
// (Keeping this as int for effcient msg payload and comparison)
static const int MIN_PEERMSG_VERSION = 1;

/**
 * Set of flags used to mark status information on the session.
 * usr and p2p subsystems makes use of this to mark status information of user and peer sessions.
 * Set flags are stored in 'flags_' bitset.
 */
enum SESSION_FLAG
{
    INBOUND = 0,
    USER_CHALLENGE_ISSUED = 1,
    USER_AUTHED = 2
};

int bin2hex(std::string &encoded_string, const unsigned char *bin, size_t bin_len);

int hex2bin(unsigned char *decoded, size_t decoded_len, std::string_view hex_str);

int64_t get_epoch_milliseconds();

int version_compare(const std::string &x, const std::string &y);

std::string_view getsv(const rapidjson::Value &v);

} // namespace util

#endif