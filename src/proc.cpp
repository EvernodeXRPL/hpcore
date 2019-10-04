#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include "proc.h"
#include "conf.h"

using namespace std;
using namespace shared;

namespace proc
{

/**
 * Keeps the currently executing contract process id (if any)
 */
int contract_pid;

void write_to_stdin(ContractExecArgs &args);
bool is_contract_running();
int exec_contract(ContractExecArgs &args);

int exec_contract(ContractExecArgs &args)
{
    if (is_contract_running())
    {
        cerr << "Contract process still running.\n";
        return -1;
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
        write_to_stdin(args);

        char *args[] = {conf::cfg.binary.data(), conf::cfg.binargs.data(), NULL};

        execv(args[0], args);
    }
    else
    {
        cerr << "fork() failed.\n";
        return -1;
    }

    return 0;
}

/**
 * Passes the input in the format:
 * {
 *   "version":"0.1",
 *   "usrfd":{ "pk1":[fd0, fd1], "pk2":[fd0, fd1] }
 * }
 */
void write_to_stdin(ContractExecArgs &args)
{
    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(_HP_VERSION_), allocator);

    Value users(kObjectType);
    for (auto &[pk, user] : (*args.users))
    {
        Value fdlist(kArrayType);
        fdlist.PushBack(user.inpipe[0], allocator);
        fdlist.PushBack(user.outpipe[1], allocator);
        users.AddMember(StringRef(user.pubkeyb64.data()), fdlist, allocator);
    }
    d.AddMember("usrfd", users, allocator);

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
        contract_pid = 0;
    }

    return false;
}

} // namespace proc