#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include "proc.hpp"
#include "conf.hpp"

namespace proc
{

/**
 * Keeps the currently executing contract process id (if any)
 */
__pid_t contract_pid = 0;

/**
 * Executes the contract process and passes the specified arguments.
 * 
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
int exec_contract(const ContractExecArgs &args)
{
    if (is_contract_running())
    {
        std::cerr << "Contract process still running.\n";
        return -1;
    }

    __pid_t pid = fork();
    if (pid > 0)
    {
        // HotPocket process.

        contract_pid = pid;
    }
    else if (pid == 0)
    {
        // Contract process.
        // Set up the process environment and overlay the contract binary program with execv().

        // Set the contract process working directory.
        chdir(conf::ctx.contractDir.data());

        // Write the contract input message from HotPocket to the stdin (0) of the contract process.
        write_to_stdin(args);

        char *execv_args[] = {conf::cfg.binary.data(), conf::cfg.binargs.data(), NULL};
        execv(execv_args[0], execv_args);
    }
    else
    {
        std::cerr << "fork() failed.\n";
        return -1;
    }

    return 0;
}

/**
 * Writes the contract input message into the stdin of the contract process.
 * Input format:
 * {
 *   "version":"<hp version>",
 *   "pubkey": "<this node's base64 public key>",
 *   "ts": <this node's timestamp (unix milliseconds)>,
 *   "usrfd":{ "pkb64":[fd0, fd1], ... },
 *   "nplfd":{ "pkb64":[fd0, fd1], ... },
 *   "unl":[ "pkb64", ... ]
 * }
 */
int write_to_stdin(const ContractExecArgs &args)
{
    //Populate the json document with contract args.

    rapidjson::Document d;
    d.SetObject();
    rapidjson::Document::AllocatorType &allocator = d.GetAllocator();

    d.AddMember("version", rapidjson::StringRef(util::HP_VERSION), allocator);
    d.AddMember("pubkey", rapidjson::StringRef(conf::cfg.pubkeyb64.data()), allocator);
    d.AddMember("ts", args.timestamp, allocator);

    rapidjson::Value users(rapidjson::kObjectType);
    for (auto &[sid, user] : args.users)
    {
        rapidjson::Value fdlist(rapidjson::kArrayType);
        fdlist.PushBack(user.inpipe[0], allocator);
        fdlist.PushBack(user.outpipe[1], allocator);
        users.AddMember(rapidjson::StringRef(user.pubkeyb64.data()), fdlist, allocator);
    }
    d.AddMember("usrfd", users, allocator);

    rapidjson::Value peers(rapidjson::kObjectType);
    for (auto &[sid, peer] : args.peers)
    {
        rapidjson::Value fdlist(rapidjson::kArrayType);
        fdlist.PushBack(peer.inpipe[0], allocator);
        fdlist.PushBack(peer.outpipe[1], allocator);
        peers.AddMember(rapidjson::StringRef(peer.pubkeyb64.data()), fdlist, allocator);
    }
    d.AddMember("nplfd", peers, allocator);

    rapidjson::Value unl(rapidjson::kArrayType);
    for (std::string &node : conf::cfg.unl)
        unl.PushBack(rapidjson::StringRef(node.data()), allocator);
    d.AddMember("unl", unl, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    d.Accept(writer);

    // Get the json string that should be written to contract input pipe.
    const char *json = buffer.GetString();

    // Establish contract input pipe.
    int stdinpipe[2];
    if (pipe(stdinpipe) != 0)
    {
        std::cerr << "Failed to create pipe to the contract process.\n";
        return -1;
    }

    // Redirect pipe read-end to the contract std input so the
    // contract process can read from our pipe.
    dup2(stdinpipe[0], STDIN_FILENO);
    close(stdinpipe[0]);

    // Write the json message and close write fd.
    write(stdinpipe[1], json, buffer.GetSize());
    close(stdinpipe[1]);

    return 0;
}

/**
 * Checks whether the contract process is running at this moment.
 */
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