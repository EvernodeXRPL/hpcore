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
    USER_CHALLENGE_ISSUED = 0,
    USER_AUTHED = 1
};

/**
 * Holds information about a HotPocket peer connected to this node.
 */
struct peer_node
{
    std::string pubkeyb64; // Base64 peer public key
    int inpipe[2];         // NPL pipe from HP to SC
    int outpipe[2];        // NPL pipe from SC to HP

    peer_node(std::string_view _pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

int base64_encode(std::string &encoded_string, const unsigned char *bin, size_t bin_len);

int base64_decode(unsigned char *decoded, size_t decoded_len, std::string_view base64_str);

int version_compare(const std::string &x, const std::string &y);

std::string_view getsv(const rapidjson::Value &v);

} // namespace util

#endif