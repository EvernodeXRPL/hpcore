#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <vector>
#include <unistd.h>
#include <sstream>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include "proc.hpp"
#include "conf.hpp"

namespace proc
{

// Enum used to differenciate pipe fds maintained for SC I/O pipes.
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

// Map of user pipe fds (map key: user public key)
std::unordered_map<std::string, std::vector<int>> userfds;

// Pipe fds for HP <--> messages.
std::vector<int> hpscfds;

// Holds the contract process id (if currently executing).
__pid_t contract_pid;

/**
 * Executes the contract process and passes the specified arguments.
 * 
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
int exec_contract(const ContractExecArgs &args)
{
    // Write any hp input messages to hp->sc pipe.
    if (write_contract_hp_inputs(args) != 0)
    {
        std::cerr << "Failed to write HP input to contract.\n";
        return -1;
    }

    // Write any verified (consensus-reached) user inputs to user pipes.
    if (write_contract_user_inputs(args) != 0)
    {
        cleanup_userfds();
        std::cerr << "Failed to write user inputs to contract.\n";
        return -1;
    }

    __id_t pid = fork();
    if (pid > 0)
    {
        // HotPocket process.
        contract_pid = pid;

        // Close all fds unused by HP process.
        close_unused_fds(true);

        // Wait for child process (contract process) to complete execution.

        int presult = await_contract_execution();
        contract_pid = 0;
        if (presult != 0)
        {
            std::cerr << "Contract process exited with non-normal status code: " << presult << std::endl;
            return -1;
        }

        // After contract execution, collect contract outputs.

        if (read_contract_hp_outputs(args) != 0)
            return -1;

        if (read_contract_user_outputs(args) != 0)
            return -1;

        userfds.clear();
    }
    else if (pid == 0)
    {
        // Contract process.
        // Set up the process environment and overlay the contract binary program with execv().

        // Close all fds unused by SC process.
        close_unused_fds(false);

        // Set the contract process working directory.
        chdir(conf::ctx.contractDir.data());

        // Write the contract input message from HotPocket to the stdin (0) of the contract process.
        write_contract_args(args);

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
 * Blocks the calling thread until the contract process compelted exeution (if running).
 * 
 * @return 0 if contract process exited normally, exit code of contract process if abnormally exited.
 */
int await_contract_execution()
{
    if (contract_pid > 0)
    {
        int scstatus;
        waitpid(contract_pid, &scstatus, 0);
        if (!WIFEXITED(scstatus))
            return WEXITSTATUS(scstatus);
    }
    return 0;
}

/**
 * Writes the contract args (JSON) into the stdin of the contract process.
 * Args format:
 * {
 *   "version":"<hp version>",
 *   "pubkey": "<this node's hex public key>",
 *   "ts": <this node's timestamp (unix milliseconds)>,
 *   "hpfd": [fd0, fd1],
 *   "usrfd":{ "<pkhex>":[fd0, fd1], ... },
 *   "nplfd":{ "<pkhex>":[fd0, fd1], ... },
 *   "unl":[ "pkhex", ... ]
 * }
 */
int write_contract_args(const ContractExecArgs &args)
{
    // Populate the json string with contract args.
    // We don't use a JSOn parser here because it's lightweight to contrstuct the
    // json string manually.

    std::ostringstream os;
    os << "{\"version\":\"" << util::HP_VERSION
       << "\",\"pubkey\":\"" << conf::cfg.pubkeyhex
       << "\",\"ts\":" << args.timestamp
       << ",\"hpfd\":[" << hpscfds[FDTYPE::SCREAD] << "," << hpscfds[FDTYPE::SCWRITE]
       << "],\"usrfd\":{";

    for (auto itr = userfds.begin(); itr != userfds.end(); itr++)
    {
        if (itr != userfds.begin())
            os << ","; // Trailing comma separator for previous element.

        // Get the hex pubkey of the user.
        std::string_view userpubkey = itr->first; // User pubkey in binary format.
        std::string userpubkeyhex;
        util::bin2hex(
            userpubkeyhex,
            reinterpret_cast<const unsigned char *>(userpubkey.data()),
            userpubkey.length());

        // Write user hex pubkey and fds.
        os << "\"" << userpubkeyhex << "\":["
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
 * Writes any hp input messages to the contract.
 */
int write_contract_hp_inputs(const ContractExecArgs &args)
{
    if (create_and_write_iopipes(hpscfds, args.hpscbufs.first) != 0) // hpscbufs.first is the input buffer.
    {
        std::cerr << "Error writing HP input to SC (" << args.hpscbufs.first.length()
                  << " bytes)" << std::endl;
        return -1;
    }
    return 0;
}

/**
 * Creates the pipes and writes verified (consesus-reached) user
 * inputs to the SC via the pipe.
 */
int write_contract_user_inputs(const ContractExecArgs &args)
{
    // Loop through input buffer for each user.
    for (auto &[pubkey, bufpair] : args.userbufs)
    {
        userfds[pubkey] = std::move(std::vector<int>());
        std::vector<int> &fds = userfds[pubkey];

        if (create_and_write_iopipes(fds, bufpair.first) != 0) // bufpair.first is the input buffer.
        {
            std::cerr << "Error writing contract input (" << bufpair.first.length()
                      << " bytes) from user" << std::endl;
            return -1;
        }
    }

    return 0;
}

/**
 * Read all HP output messages produced by the contract process and store them in
 * the buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_hp_outputs(const ContractExecArgs &args)
{
    // Clear the input buffer because we are sure the contract has finished reading from
    // that mapped memory portion.
    args.hpscbufs.first.clear(); //bufpair.first is the input buffer.

    if (read_iopipe(hpscfds, args.hpscbufs.second) != 0) // hpscbufs.second is the output buffer.
    {
        std::cerr << "Error reading HP output";
        return -1;
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
    for (auto &[pubkey, bufpair] : args.userbufs)
    {
        // Clear the input buffer because we are sure the contract has finished reading from
        // that mapped memory portion.
        bufpair.first.clear(); //bufpair.first is the input buffer.

        // Get fds for the user by pubkey.
        std::vector<int> &fds = userfds[pubkey];

        if (read_iopipe(fds, bufpair.second) != 0) // bufpair.second is the output buffer.
        {
            std::cerr << "Error reading contract output for user "
                      << pubkey << std::endl;
        }
    }

    return 0;
}

/**
 * Closes any open user fds after an error.
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

/**
 * Common function to create a pair of pipes (Hp->SC, SC->HP) and write the
 * given input buffer into the write fd from the HP side.
 * 
 * @param fds Vector to populate fd list.
 * @param inputbuffer Buffer to write into the HP write fd.
 */
int create_and_write_iopipes(std::vector<int> &fds, std::string &inputbuffer)
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

    // If both pipes got created, assign them to the fd vector.
    fds.clear();
    fds.push_back(inpipe[0]);  //SCREAD
    fds.push_back(inpipe[1]);  //HPWRITE
    fds.push_back(outpipe[0]); //HPREAD
    fds.push_back(outpipe[1]); //SCWRITE

    // Write the input (if any) into the contract and close the writefd.

    int writefd = fds[FDTYPE::HPWRITE];
    bool vmsplice_error = false;

    if (!inputbuffer.empty())
    {
        // We use vmsplice to map (zero-copy) the input into the fd.
        iovec memsegs[1];
        memsegs[0].iov_base = inputbuffer.data();
        memsegs[0].iov_len = inputbuffer.length();

        if (vmsplice(writefd, memsegs, 1, 0) == -1)
            vmsplice_error = true;

        // It's important that we DO NOT clear the input buffer string until the contract
        // process has actually read from the fd. Because the OS is just mapping our
        // input buffer memory portion into the fd, if we clear it now, the contract process
        // will get invaid bytes when reading the fd.
    }

    // Close the writefd since we no longer need it.
    close(writefd);
    fds[FDTYPE::HPWRITE] = 0;

    return vmsplice_error ? -1 : 0;
}

/**
 * Common function to read SC output from the pipe and populate a given buffer.
 * @param fds Vector representing the pipes fd list.
 * @param The buffer to place the read output.
 */
int read_iopipe(std::vector<int> &fds, std::string &outputbuffer)
{
    // Read any outputs that have been written by the contract process
    // from the HP outpipe and store in the outbuffer.
    // outbuffer will be read by the consensus process later when it wishes so.

    int readfd = fds[FDTYPE::HPREAD];
    int bytes_available = 0;
    ioctl(readfd, FIONREAD, &bytes_available);
    bool vmsplice_error = false;

    if (bytes_available > 0)
    {
        outputbuffer.resize(bytes_available); // args.hpscbufs.second is the output buffer.

        // Populate the user output buffer with new data from the pipe.
        // We use vmsplice to map (zero-copy) the output from the fd into output bbuffer.
        iovec memsegs[1];
        memsegs[0].iov_base = outputbuffer.data();
        memsegs[0].iov_len = bytes_available;

        if (vmsplice(readfd, memsegs, 1, 0) == -1)
            vmsplice_error = true;
    }

    // Close readfd fd on HP process side because we are done with contract process I/O.
    close(readfd);
    fds[FDTYPE::HPREAD] = 0;

    return vmsplice_error ? -1 : 0;
}

void close_unused_fds(bool is_hp)
{
    close_unused_vectorfds(is_hp, hpscfds);

    // Loop through user fds.
    for (auto &[pubkey, fds] : userfds)
        close_unused_vectorfds(is_hp, fds);
}

/**
 * Common function for closing unused fds based on which process this gets called from.
 * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
 * @param fds Vector of fds to close.
 */
void close_unused_vectorfds(bool is_hp, std::vector<int> &fds)
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

        // HPWRITE fd has aleady been closed by HP process after writing
        // inputs (before the fork).
    }
}

} // namespace proc