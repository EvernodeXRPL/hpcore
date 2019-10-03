#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "../shared.h"
#include "usr.h"

using namespace std;
using namespace shared;

namespace usr
{

map<string, ContractUser> users;

void add_user(string pubkeyb64)
{
    if (users.count(pubkeyb64) == 1)
    {
        cerr << pubkeyb64 << " already exist. Cannot add user.\n";
        return;
    }

    int inpipe[2];
    int outpipe[2];
    if (pipe(inpipe) != 0 || pipe(outpipe) != 0) {
        cerr << "User pipe creation failed. pubkey:" << pubkeyb64 << endl;
        return;
    }

    users.insert(pair<string, ContractUser>(pubkeyb64, ContractUser(pubkeyb64, inpipe, outpipe)));
}

void remove_user(string pubkeyb64)
{
    if (users.count(pubkeyb64) == 0)
    {
        cerr << pubkeyb64 << " does not exist. Cannot remove user.\n";
        return;
    }

    auto itr = users.find(pubkeyb64);
    ContractUser user = itr->second;
    close(user.inpipe[0]);
    close(user.inpipe[1]);
    close(user.outpipe[0]);
    close(user.outpipe[1]);

    users.erase(itr);
}

//Read per-user outputs produced by the contract process.
int read_contract_user_outputs()
{
    for (auto& [pk, user] : users)
    {
        int fdout = user.outpipe[0];
        int bytes_available = 0;
        ioctl(fdout, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            unsigned char data[bytes_available];
            read(fdout, data, bytes_available);

            //Replace the existing user buffer with new buffer
            vector<unsigned char> buffer(data, data + bytes_available);
            user.outbuffer.swap(buffer);

            cout << "Read " + to_string(bytes_available) << " bytes into user output buffer. user:" + user.pubkeyb64 << endl;
        }
    }

    return 1;
}

} // namespace usr