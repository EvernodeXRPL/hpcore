#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "proc.h"
#include "conf.h"

using namespace std;

namespace proc
{

map<int, ProcInfo> pidmap;

void write_to_stdin(string str);

int exec_contract()
{
    int requestpipe[2];
    int replypipe[2];

    if (pipe(requestpipe) != 0 || pipe(replypipe) != 0)
    {
        cerr << "Error opening pipes.\n";
        return 0;
    }

    int pid = fork();
    if (pid > 0)
    {
        //Close the fds the hotpocket process doesn't need.
        close(requestpipe[0]);
        close(replypipe[1]);

        ProcInfo procinfo;
        procinfo.requestpipe[0] = requestpipe[0]; //Request read fd - Read by contract proc.
        procinfo.requestpipe[1] = requestpipe[1]; //Request write fd - Written by hp proc.
        procinfo.replypipe[0] = replypipe[0];     //Reply read fd - Read by hp proc.
        procinfo.replypipe[1] = replypipe[1];     //Reply write fd - Written by contract proc.
        pidmap.insert(pair<int, ProcInfo>(pid, procinfo));

        write(requestpipe[1], "MsgfromHP", 10);
    }
    else
    {
        //In this block, we are inside the contract process.
        //We will setup the process environment, and then call execv()
        //to overlay the process with the actual contract binary program code.

        //Close the fds the contract process doesn't need.
        close(requestpipe[1]);
        close(replypipe[0]);
        
        //Set the contract process working directory.
        chdir(conf::ctx.contractDir.data());

        //Write the contract input to the stdin (0) of the contract process.
        string input = to_string(requestpipe[0]) + "|" + to_string(replypipe[1]);
        write_to_stdin(input);

        char *args[] =
            {conf::cfg.binary.data(),
             conf::cfg.binargs.data(),
             NULL};

        execv(args[0], args);
    }
}

void write_to_stdin(string str)
{
    int stdinpipe[2];
    pipe(stdinpipe);
    dup2(stdinpipe[0], STDIN_FILENO);
    close(stdinpipe[0]);

    write(stdinpipe[1], str.data(), str.size() + 1);
    close(stdinpipe[1]);
}

//Read outputs from all running contracts.
void read_contract_outputs()
{
    for (pair<int, ProcInfo> p : pidmap)
    {
        int pid = p.first;
        ProcInfo &procinfo = p.second;
        int replyfd = procinfo.replypipe[0];

        int bytes_available = 0;
        ioctl(replyfd, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            char data[bytes_available];
            read(replyfd, data, bytes_available);
            cout << "pid:" << pid << " data: " << data << endl;
        }
        else
        {
            cout << "pid:" << pid << " data: NULL" << endl;

        }
    }
}

} // namespace proc