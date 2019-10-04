#ifndef _HP_SHARED_H_
#define _HP_SHARED_H_

#include <string>
#include <vector>

using namespace std;

namespace shared
{

struct ContractUser
{
    string pubkeyb64;
    int inpipe[2];
    int outpipe[2];
    vector<unsigned char> outbuffer;

    ContractUser(string _pubkeyb64, int _inpipe[2], int _outpipe[2])
    {
        pubkeyb64 = _pubkeyb64;
        inpipe[0] = _inpipe[0];
        inpipe[1] = _inpipe[1];
        outpipe[0] = _outpipe[0];
        outpipe[1] = _outpipe[1];
    }
};

int base64_encode(unsigned char *bin, size_t bin_len, string &encoded_string);
int base64_decode(string base64_str, unsigned char *decoded, size_t decoded_len);

} // namespace usr

#endif