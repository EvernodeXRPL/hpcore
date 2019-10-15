#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "proc.hpp"
#include "usr/usr.hpp"
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

    if (create_userpipes() != 0)
    {
        std::cerr << "User pipe creation failed.\n";
        return -1;
    }

    __pid_t pid = fork();
    if (pid > 0)
    {
        // HotPocket process.

        contract_pid = pid;

        // Close all user fds unused by HP process.
        close_unused_userfds(true);
    }
    else if (pid == 0)
    {
        // Contract process.
        // Set up the process environment and overlay the contract binary program with execv().

        // Close all user fds unused by SC process.
        close_unused_userfds(false);

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
 * Create pipes for all authed users in order to perform I/O with SC.
 */
int create_userpipes()
{
    for (auto &[k, user] : usr::users)
    {
        int inpipe[2];
        if (pipe(inpipe) != 0)
        {
            //Abandon and cleanup.
            cleanup_userfds(user);
            return -1;
        }

        int outpipe[2];
        if (pipe(outpipe) != 0)
        {
            // Close the earlier created pipe.
            close(inpipe[0]);
            close(inpipe[1]);

            inpipe[0] = 0;
            inpipe[1] = 0;

            //Abandon and cleanup.
            cleanup_userfds(user);
            return -1;
        }
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
 *   "usrfd":{ "<pkb64>":[fd0, fd1], ... },
 *   "nplfd":{ "<pkb64>":[fd0, fd1], ... },
 *   "unl":[ "pkb64", ... ]
 * }
 */
int write_to_stdin(const ContractExecArgs &args)
{
    // Populate the json strring with contract args.
    // We don't use a JSOn parser here because it's lightweight to contrstuct the
    // json string manually.

    std::ostringstream os;
    os << "{\"version:\"" << util::HP_VERSION
       << "\",\"pubkey\":\"" << conf::cfg.pubkeyb64
       << "\",\"ts\":" << args.timestamp
       << ",\"usrfd\":{";

    for (auto itr = usr::users.begin(); itr != usr::users.end(); itr++)
    {
        if (itr != usr::users.begin())
            os << ","; // Trailing comma separator for previous element.

        usr::contract_user user = itr->second;
        os << "\"" << user.pubkeyb64 << "\":["
           << user.fds[usr::USERFDTYPE::SCREAD] << ","
           << user.fds[usr::USERFDTYPE::SCWRITE] << "]";
    }

    os << "},\"nplfd\":{},\"unl\":[";

    for (auto node = conf::cfg.unl.begin(); node != conf::cfg.unl.end(); node++)
    {
        if (node != conf::cfg.unl.begin())
            os << ","; // Trailing comma separator for previous element.

        os << "\"" << *node << "\"";
    }

    os << "]}";

    // Get the json string that should be written to contract input pipe.
    std::string json = os.str();

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
    write(stdinpipe[1], json.data(), json.size() + 1);
    close(stdinpipe[1]);

    return 0;
}

/**
 * Read all per-user outputs produced by the contract process and store them in
 * the user buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_user_outputs()
{
    // Read any outputs that have been written by the contract process
    // from all the user outpipes and store in the outbuffer of each user.
    // User outbuffer will be read by the consensus process later when it wishes so.

    // Future optmization: Read and populate user buffers parallely.
    // Currently this is sequential for simplicity which will not scale well
    // when there are large number of users connected to the same HP node.

    for (auto &[sid, user] : usr::users)
    {
        int fdout = user.fds[usr::USERFDTYPE::HPREAD];
        int bytes_available = 0;
        ioctl(fdout, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            char data[bytes_available];
            read(fdout, data, bytes_available);

            // Populate the user output buffer with new data
            user.outbuffer = std::string(data, bytes_available);

            // Close remaining fds on HP process side because we are done with contract process I/O.
            close(user.fds[usr::USERFDTYPE::HPREAD]);
            close(user.fds[usr::USERFDTYPE::HPWRITE]);

            std::cout << "Read " + std::to_string(bytes_available) << " bytes into user output buffer. user:" + user.pubkeyb64 << std::endl;
        }
    }

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

/**
 * Closes unused user fds based on which process this gets called from.
 */
void close_unused_userfds(bool is_hp)
{
    for (auto &[sid, user] : usr::users)
    {
        if (is_hp)
        {
            // Close unused fds in Hot Pocket process.
            close(user.fds[usr::USERFDTYPE::SCREAD]);
            close(user.fds[usr::USERFDTYPE::SCWRITE]);
        }
        else
        {
            // Close unused fds in smart contract process.
            close(user.fds[usr::USERFDTYPE::HPREAD]);
            close(user.fds[usr::USERFDTYPE::HPWRITE]);
        }
    }
}

/**
 * Cleanup any open fds of all users (called after partial pipe failure).
 * 
 * @param upto The user upto which point should be checked for open fds.
 */
void cleanup_userfds(const usr::contract_user &upto)
{
    for (auto &[sid, user] : usr::users)
    {
        if (&user == &upto)
            break;

        for (int i = 0; i < 4; i++)
        {
            if (user.fds[i] > 0)
            {
                close(user.fds[i]);
                user.fds[i] = 0;
            }
        }
    }
}

} // namespace proc