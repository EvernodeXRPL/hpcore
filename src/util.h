#ifndef _HP_UTIL_H_
#define _HP_UTIL_H_

#include <string>
#include <vector>

using namespace std;

namespace util
{

struct ContractUser
{
    string pubkeyb64;
    int inpipe[2];
    int outpipe[2];
    string outbuffer;

    ContractUser(string _pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

struct PeerNode
{
    string pubkeyb64;
    int inpipe[2];
    int outpipe[2];

    PeerNode(string _pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

int base64_encode(const unsigned char *bin, size_t bin_len, string &encoded_string);
int base64_decode(const string &base64_str, unsigned char *decoded, size_t decoded_len);
void replace_string_contents(string &str, const char* bytes, size_t bytes_len);
int version_compare(const string &v1, const string &v2);

} // namespace usr

#endif