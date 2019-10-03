#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <rapidjson/document.h>
#include "rapidjson/stringbuffer.h"
#include <rapidjson/writer.h>
#include "proc.h"
#include "conf.h"

using namespace std;

namespace proc
{

/**
 * Keeps the currently executing contract process id (if any)
 */
int contract_pid;

void write_to_stdin(ContractExecArgs &msg);
bool is_contract_running();
int exec_contract(ContractExecArgs &msg);
int read_contract_outputs(vector<ContractUser> users);

int exec_contract(ContractExecArgs &msg)
{
    if (is_contract_running())
    {
        cerr << "Contract process still running.\n";
        return 0;
    }

    int pid = fork();
    if (pid > 0)
    {
        contract_pid = pid;
    }
    else if (pid == 0)
    {
        //Set the contract process working directory.
        chdir(conf::ctx.contractDir.data());

        //Write the contract args to the stdin (0) of the contract process.
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

//Read per-user outputs produced by the contract process.
int read_contract_outputs(vector<ContractUser> users)
{
    if (is_contract_running())
    {
        cerr << "Contract process still running.\n";
        return 0;
    }
    
    for (ContractUser user : users)
    {
        int fdout = user.outpipe[0];
        int bytes_available = 0;
        ioctl(fdout, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            char data[bytes_available];
            read(fdout, data, bytes_available);
            cout << "user:" << user.pubkeyb64 << " reply: '" << data << "'" << endl;
        }
    }

    return 1;
}

void write_to_stdin(ContractExecArgs &msg)
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

bool is_contract_running()
{
    if (contract_pid > 0)
    {
        int status = 0;
        if (!waitpid(contract_pid, &status, WNOHANG))
            return true;
    }

    contract_pid = 0;
    return false;
}

} // namespace proc