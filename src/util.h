#ifndef _HP_UTIL_H_
#define _HP_UTIL_H_

#include <string>
#include <vector>

using namespace std;

namespace util
{

/**
 * Holds information about an authenticated (challenge-verified) user
 * connected to the HotPocket node.
 */
struct contract_user
{
    string pubkeyb64;   // Base64 user public key
    int inpipe[2];      // Pipe to receive user input
    int outpipe[2];     // Pipe to receive output produced by the contract
    string outbuffer;   // Holds the contract output to be processed by consensus rounds

    contract_user(const string &_pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

/**
 * Holds information about a HotPocket peer connected to this node.
 */
struct peer_node
{
    string pubkeyb64;   // Base64 peer public key
    int inpipe[2];      // NPL pipe from HP to SC
    int outpipe[2];     // NPL pipe from SC to HP

    peer_node(const string &_pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

/**
 * Encodes provided bytes to base64 string.
 * 
 * @param bin Bytes to encode.
 * @param bin_len Bytes length.
 * @param encoded_string String reference to assign the base64 encoded output.
 */
int base64_encode(const unsigned char *bin, size_t bin_len, string &encoded_string);

/**
 * Decodes provided base64 string into bytes.
 * 
 * @param base64_str Base64 string to decode.
 * @param decoded Decoded bytes.
 * @param decoded_len Decoded bytes length.
 */
int base64_decode(const string &base64_str, unsigned char *decoded, size_t decoded_len);

/**
 * Replaces contents of the given string with provided bytes.
 * 
 * @param str String reference to replace contents.
 * @param bytes Bytes to write into the string.
 * @param bytes_len Bytes length.
 */
void replace_string_contents(string &str, const char* bytes, size_t bytes_len);

/**
 * Compare two version strings in the format of "1.12.3".
 * v1 <  v2  -> returns -1
 * v1 == v2  -> returns  0
 * v1 >  v2  -> returns +1
 */
int version_compare(const string &v1, const string &v2);

} // namespace usr

#endif