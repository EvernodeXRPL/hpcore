#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <vector>
#include <unistd.h>
#include <sstream>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "proc.hpp"
#include "conf.hpp"

namespace proc
{

/**
 * Enum used to differenciate pipe fds maintained for SC I/O pipes.
 */
enum FDTYPE
{
    // Used by Smart Contract to read input sent by Hot Pocket
    SCREAD = 0,
    // Used by Hot Pocket to write input to the smart contract.
    HPWRITE = 1,
    // Used by Hot Pocket to read output from the smart contract.
    HPREAD = 2,
    // Used by Smart Contract to write output back to Hot Pocket.
    SCWRITE = 3
};

/**
 * Map of user pipe fds (map key: user public key)
 */
std::unordered_map<std::string, std::vector<int>> userfds;

/**
 * Executes the contract process and passes the specified arguments.
 * 
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
int exec_contract(const ContractExecArgs &args)
{
    // Write any verified (consensus-reached) user inputs to user pipes.
    if (write_verified_user_inputs(args) != 0)
    {
        cleanup_userfds();
        std::cerr << "Failed to write user inputs to contract.\n";
        return -1;
    }

    __pid_t pid = fork();
    if (pid > 0)
    {
        // HotPocket process.

        // Close all user fds unused by HP process.
        close_unused_userfds(true);

        // Wait for child process (contract process) to complete execution.
        int scstatus;
        wait(&scstatus);
        if (!WIFEXITED(scstatus))
        {
            std::cerr << "Contract process exited with non-normal status code: "
                      << WEXITSTATUS(scstatus) << std::endl;
            return -1;
        }

        // After contract execution, collect contract user outputs.
        if (read_contract_user_outputs(args) != 0)
        {
            std::cerr << "Failed to read user outputs from contract.\n";
            return -1;
        };
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
    os << "{\"version\":\"" << util::HP_VERSION
       << "\",\"pubkey\":\"" << conf::cfg.pubkeyb64
       << "\",\"ts\":" << args.timestamp
       << ",\"usrfd\":{";

    for (auto itr = userfds.begin(); itr != userfds.end(); itr++)
    {
        if (itr != userfds.begin())
            os << ","; // Trailing comma separator for previous element.

        // Write user pubkey and fds.
        os << "\"" << itr->first << "\":["
           << itr->second[FDTYPE::SCREAD] << ","
           << itr->second[FDTYPE::SCWRITE] << "]";
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
    write(stdinpipe[1], json.data(), json.size());
    close(stdinpipe[1]);

    return 0;
}

/**
 * Creates the pipes and writes verified (consesus-reached) user
 * input to the SC via the pipe.
 */
int write_verified_user_inputs(const ContractExecArgs &args)
{
    for (auto &[pubkey, bufpair] : args.userbufs)
    {
        int inpipe[2];
        if (pipe(inpipe) != 0)
            return -1;

        int outpipe[2];
        if (pipe(outpipe) != 0)
        {
            // Close the earlier created pipe.
            close(inpipe[0]);
            close(inpipe[1]);
            return -1;
        }

        // If both pipes got created, assign them to the fd map.
        std::vector<int> fds;
        fds.push_back(inpipe[0]);  //SCREAD
        fds.push_back(inpipe[1]);  //HPWRITE
        fds.push_back(outpipe[0]); //HPREAD
        fds.push_back(outpipe[1]); //SCWRITE
        userfds[pubkey] = fds;

        // Write the user input into the contract and close the writefd.
        // We use vmsplice to map (zero-copy) the user input into the fd.
        iovec memsegs[1];
        memsegs[0].iov_base = bufpair.first.data(); // bufpair.first is the input buffer.
        memsegs[0].iov_len = bufpair.first.length();
        int writefd = fds[FDTYPE::HPWRITE];

        if (vmsplice(writefd, memsegs, 1, 0) == -1)
        {
            std::cerr << "Error writing contract input (" << bufpair.first.length()
                      << " bytes) from user " << pubkey << std::endl;
        }

        // Close the writefd since we no longer need it for this round.
        close(writefd);
        fds[FDTYPE::HPWRITE] = 0;
    }

    return 0;
}

/**
 * Read all per-user outputs produced by the contract process and store them in
 * the user buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_user_outputs(const ContractExecArgs &args)
{
    // Read any outputs that have been written by the contract process
    // from all the user outpipes and store in the outbuffer of each user.
    // User outbuffer will be read by the consensus process later when it wishes so.

    // Future optmization: Read and populate user buffers parallely.
    // Currently this is sequential for simplicity which will not scale well
    // when there are large number of users connected to the same HP node.

    for (auto &[pubkey, bufpair] : args.userbufs)
    {
        // Get fds for the user by pubkey.
        std::vector<int> &fds = userfds[pubkey];
        int readfd = fds[FDTYPE::HPREAD];
        int bytes_available = 0;
        ioctl(readfd, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            bufpair.second.reserve(bytes_available); // bufpair.second is the output buffer.

            // Populate the user output buffer with new data from the pipe.
            // We use vmsplice to map (zero-copy) the output from the fd.
            iovec memsegs[1];
            memsegs[0].iov_base = bufpair.second.data();
            memsegs[0].iov_len = bytes_available;

            if (vmsplice(readfd, memsegs, 1, 0) == -1)
            {
                std::cerr << "Error reading contract output for user "
                          << pubkey << std::endl;
            }
            else
            {
                std::cout << "Contract produced " << bytes_available << " bytes for user " << pubkey << std::endl;
            }
        }

        // Close readfd fd on HP process side because we are done with contract process I/O.
        close(readfd);
        fds[FDTYPE::HPREAD] = 0;
    }

    return 0;
}

/**
 * Closes unused user fds based on which process this gets called from.
 */
void close_unused_userfds(bool is_hp)
{
    for (auto &[pubkey, fds] : userfds)
    {
        if (is_hp)
        {
            // Close unused fds in Hot Pocket process.
            close(fds[FDTYPE::SCREAD]);
            fds[FDTYPE::SCREAD] = 0;
            close(fds[FDTYPE::SCWRITE]);
            fds[FDTYPE::SCWRITE] = 0;
        }
        else
        {
            // Close unused fds in smart contract process.
            close(fds[FDTYPE::HPREAD]);
            fds[FDTYPE::HPREAD] = 0;

            // HPWRITE fd has aleady been closed by HP process after writing user
            // inputs (before the fork).
        }
    }
}

/**
 * Closes any open user fds based after an error.
 */
void cleanup_userfds()
{
    for (auto &[pubkey, fds] : userfds)
    {
        for (int i = 0; i < 4; i++)
        {
            if (fds[i] > 0)
                close(fds[i]);
            fds[i] = 0;
        }
    }
}

} // namespace proc