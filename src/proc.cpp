#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <rapidjson/document.h>
#include "rapidjson/stringbuffer.h"
#include <rapidjson/writer.h>
#include "proc.h"
#include "conf.h"

using namespace std;

namespace proc
{

map<int, ProcInfo> pidmap;

void write_to_stdin(ContractInputMsg &msg);

int exec_contract(ContractInputMsg &msg)
{
    int pid = fork();
    if (pid > 0)
    {
        ProcInfo procinfo;
        procinfo.users = msg.users;
        pidmap.insert(pair<int, ProcInfo>(pid, procinfo));
    }
    else if (pid == 0)
    {
        //Set the contract process working directory.
        chdir(conf::ctx.contractDir.data());

        //Write the contract input to the stdin (0) of the contract process.
        write_to_stdin(msg);

        char *args[] = {conf::cfg.binary.data(), conf::cfg.binargs.data(), NULL};

        execv(args[0], args);
    }
    else
    {
        cerr << "fork() failed.\n";
        return 0;
    }

    return 1;
}

void write_to_stdin(ContractInputMsg &msg)
{
    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(_HP_VERSION_), allocator);

    Value users(kArrayType);
    for (ContractUser user : msg.users)
    {
        Value v;
        v.SetObject();
        v.AddMember("fdin", user.inpipe[0], allocator);
        v.AddMember("fdout", user.outpipe[1], allocator);
        users.PushBack(v, allocator);
    }
    d.AddMember("users", users, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    d.Accept(writer);
    const char *json = buffer.GetString();

    int stdinpipe[2];
    pipe(stdinpipe);
    dup2(stdinpipe[0], STDIN_FILENO);
    close(stdinpipe[0]);

    write(stdinpipe[1], json, strlen(json));
    close(stdinpipe[1]);
}

//Read per-user outputs from all running contract processes.
void read_contract_outputs()
{
    for (pair<int, ProcInfo> p : pidmap)
    {
        int pid = p.first;
        ProcInfo &procinfo = p.second;

        for (ContractUser user : procinfo.users)
        {
            int fdout = user.outpipe[0];
            int bytes_available = 0;
            ioctl(fdout, FIONREAD, &bytes_available);

            if (bytes_available > 0)
            {
                char data[bytes_available];
                read(fdout, data, bytes_available);
                cout << "pid:" << pid << " user:" << user.pubkeyb64
                     << " reply: '" << data << "'" << endl;
            }
        }
    }
}

} // namespace proc