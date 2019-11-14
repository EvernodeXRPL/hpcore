#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../fbschema/common_helpers.hpp"
#include "../fbschema/p2pmsg_container_generated.h"
#include "../fbschema/p2pmsg_content_generated.h"
#include "proc.hpp"
#include "ptrace_capture.hpp"

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
contract_fdmap_t userfds;

// Pipe fds for NPL <--> messages.
std::vector<int> nplfds;

// Pipe fds for HP <--> messages.
std::vector<int> hpscfds;

// Holds the contract process id (if currently executing).
pid_t contract_pid;

/**
 * Executes the contract process and passes the specified arguments.
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
int exec_contract(const contract_exec_args &args)
{
    // Setup io pipes and feed all inputs to them.
    create_iopipes_for_fdmap(userfds, args.userbufs);
    create_iopipes(nplfds);
    create_iopipes(hpscfds);

    if (feed_inputs(args) != 0)
        return -1;

    const pid_t pid = fork();
    if (pid > 0)
    {
        // HotPocket process.
        contract_pid = pid;

        // Close all fds unused by HP process.
        close_unused_fds(true);

        // Capture child process (contract process) until it completes execution.
        // This call will return when the contract process exits.
        const int presult = ptrace_capture(contract_pid, args.state_updates);
        LOG_INFO << "Contract process ended.";

        contract_pid = 0;
        if (presult != 0)
        {
            LOG_ERR << "Contract process exited with non-normal status code: " << presult;
            return -1;
        }

        // After contract execution, collect contract outputs.
        if (fetch_outputs(args) != 0)
            return -1;
    }
    else if (pid == 0)
    {
        // Contract process.
        // Set up the process environment and overlay the contract binary program with execv().

        // Close all fds unused by SC process.
        close_unused_fds(false);

        // Write the contract input message from HotPocket to the stdin (0) of the contract process.
        write_contract_args(args);

        LOG_INFO << "Starting contract process...";

        char *execv_args[] = {conf::cfg.binary.data(), conf::cfg.binargs.data(), NULL};

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(execv_args[0], execv_args);
    }
    else
    {
        LOG_ERR << "fork() failed.";
        return -1;
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
 *   "nplfd":[fd0, fd1],
 *   "unl":[ "pkhex", ... ]
 * }
 */
int write_contract_args(const contract_exec_args &args)
{
    // Populate the json string with contract args.
    // We don't use a JSON parser here because it's lightweight to contrstuct the
    // json string manually.

    std::ostringstream os;
    os << "{\"version\":\"" << util::HP_VERSION
       << "\",\"pubkey\":\"" << conf::cfg.pubkeyhex
       << "\",\"ts\":" << args.timestamp
       << ",\"hpfd\":[" << hpscfds[FDTYPE::SCREAD] << "," << hpscfds[FDTYPE::SCWRITE]
       << "],\"usrfd\":{";

    fdmap_json_to_stream(userfds, os);

    os << "},\"nplfd\":[" << nplfds[FDTYPE::SCREAD] << "," << nplfds[FDTYPE::SCWRITE]
       << "],\"unl\":[";

    for (auto nodepk = conf::cfg.unl.begin(); nodepk != conf::cfg.unl.end(); nodepk++)
    {
        if (nodepk != conf::cfg.unl.begin())
            os << ","; // Trailing comma separator for previous element.

        // Convert binary nodepk into hex.
        std::string pubkeyhex;
        util::bin2hex(
            pubkeyhex,
            reinterpret_cast<const unsigned char *>((*nodepk).data()),
            (*nodepk).length());

        os << "\"" << pubkeyhex << "\"";
    }

    os << "]}";

    // Get the json string that should be written to contract input pipe.
    const std::string json = os.str();

    // Establish contract input pipe.
    int stdinpipe[2];
    if (pipe(stdinpipe) != 0)
    {
        LOG_ERR << "Failed to create pipe to the contract process.";
        return -1;
    }

    // Redirect pipe read-end to the contract std input so the
    // contract process can read from our pipe.
    dup2(stdinpipe[0], STDIN_FILENO);
    close(stdinpipe[0]);

    // Write the json message and close write fd.
    if (write(stdinpipe[1], json.data(), json.size()) == -1)
    {
        LOG_ERR << "Failed to write to stdin of contract process.";
        return -1;
    }
    close(stdinpipe[1]);

    return 0;
}

int feed_inputs(const contract_exec_args &args)
{
    // Write any hp or npl input messages to hp->sc and npl->sc pipe.
    if (write_contract_hp_npl_inputs(args) != 0)
    {
        LOG_ERR << "Failed to write HP or NPL inputs to contract.";
        return -1;
    }

    // Write any verified (consensus-reached) user inputs to user pipes.
    if (write_contract_fdmap_inputs(userfds, args.userbufs) != 0)
    {
        cleanup_fdmap(userfds);
        LOG_ERR << "Failed to write user inputs to contract.";
        return -1;
    }

    return 0;
}

int fetch_outputs(const contract_exec_args &args)
{
    if (read_contract_hp_npl_outputs(args) != 0)
    {
        LOG_ERR << "Error reading HP or NPL output from the contract.";
        return -1;
    }

    if (read_contract_fdmap_outputs(userfds, args.userbufs) != 0)
    {
        LOG_ERR << "Error reading User output from the contract.";
        return -1;
    }

    nplfds.clear();
    userfds.clear();
    return 0;
}

/**
 * Writes any hp input messages to the contract.
 */
int write_contract_hp_npl_inputs(const contract_exec_args &args)
{
    if (write_iopipe(hpscfds, args.hpscbufs.inputs) != 0)
    {
        LOG_ERR << "Error writing HP inputs to SC";
        return -1;
    }

    if (write_npl_iopipe(nplfds, args.nplbuff.inputs) != 0)
    {
        LOG_ERR << "Error writing NPL inputs to SC";
        return -1;
    }

    return 0;
}

/**
 * Read all HP output messages produced by the contract process and store them in
 * the buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_hp_npl_outputs(const contract_exec_args &args)
{
    // Clear the input buffers because we are sure the contract has finished reading from
    // that mapped memory portion.
    args.hpscbufs.inputs.clear();

    if (read_iopipe(hpscfds, args.hpscbufs.output) != 0) // hpscbufs.second is the output buffer.
    {
        LOG_ERR << "Error reading HP output from the contract.";
        return -1;
    }

    if (read_iopipe(nplfds, args.nplbuff.output) != 0) // hpscbufs.second is the output buffer.
    {
        LOG_ERR << "Error reading NPL output from the contract.";
        return -1;
    }

    return 0;
}

/**
 * Common helper function to write json output of fdmap to given ostream.
 * @param fdmap Any pubkey->fdlist map. (eg. userfds, nplfds)
 * @param os An output stream.
 */
void fdmap_json_to_stream(const contract_fdmap_t &fdmap, std::ostringstream &os)
{
    for (auto itr = fdmap.begin(); itr != fdmap.end(); itr++)
    {
        if (itr != fdmap.begin())
            os << ","; // Trailing comma separator for previous element.

        // Get the hex pubkey.
        std::string_view pubkey = itr->first; // Pubkey in binary format.
        std::string pubkeyhex;
        util::bin2hex(
            pubkeyhex,
            reinterpret_cast<const unsigned char *>(pubkey.data()),
            pubkey.length());

        // Write  hex pubkey and fds.
        os << "\"" << pubkeyhex << "\":["
           << itr->second[FDTYPE::SCREAD] << ","
           << itr->second[FDTYPE::SCWRITE] << "]";
    }
}

/**
 * Creates io pipes for all pubkeys specified in bufmap.
 * @param fdmap A map which has public key and a vector<int> as fd list for that public key.
 * @param bufmap A map which has a public key and input/output buffer lists for that public key.
 * @return 0 on success. -1 on failure.
 */
int create_iopipes_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
{
    for (auto &[pubkey, buflist] : bufmap)
    {
        std::vector<int> fds = std::vector<int>();
        if (create_iopipes(fds) != 0)
            return -1;

        fdmap.emplace(pubkey, std::move(fds));
    }

    return 0;
}

/**
 * Common function to create the pipes and write buffer inputs to the fdmap.
 * We take mutable parameters since the internal entries in the maps will be
 * modified (eg. fd close, buffer clear).
 * 
 * @param fdmap A map which has public key and a vector<int> as fd list for that public key.
 * @param bufmap A map which has a public key and input/output buffer lists for that public key.
 * @return 0 on success. -1 on failure.
 */
int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
{
    // Loop through input buffers for each pubkey.
    for (auto &[pubkey, buflist] : bufmap)
    {
        if (write_iopipe(fdmap[pubkey], buflist.inputs) != 0)
            return -1;
    }

    return 0;
}

/**
 * Common function to read all outputs produced by the contract process and store them in
 * output buffers for later processing.
 * 
 * @param fdmap A map which has public key and a vector<int> as fd list for that public key.
 * @param bufmap A map which has a public key and input/output buffer pair for that public key.
 * @return 0 on success. -1 on failure.
 */
int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
{
    for (auto &[pubkey, bufpair] : bufmap)
    {
        // Clear the input buffer because we are sure the contract has finished reading from
        // the inputs' mapped memory portion.
        bufpair.inputs.clear();

        // Get fds for the pubkey.
        std::vector<int> &fds = fdmap[pubkey];

        if (read_iopipe(fds, bufpair.output) != 0) // bufpair.second is the output buffer.
            return -1;
    }

    return 0;
}

/**
 * Common function to close any open fds in the map after an error.
 * @param fdmap Any pubkey->fdlist map. (eg. userfds, nplfds)
 */
void cleanup_fdmap(contract_fdmap_t &fdmap)
{
    for (auto &[pubkey, fds] : fdmap)
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
 * Common function to create a pair of pipes (Hp->SC, SC->HP).
 * @param fds Vector to populate fd list.
 * @param inputbuffer Buffer to write into the HP write fd.
 */
int create_iopipes(std::vector<int> &fds)
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

    return 0;
}

/**
 * Common function to write the given input buffer into the write fd from the HP side.
 * @param fds Vector of fd list.
 * @param inputs Buffer to write into the HP write fd.
 */
int write_iopipe(std::vector<int> &fds, std::list<std::string> &inputs)
{
    // Write the inputs (if any) into the contract and close the writefd.

    const int writefd = fds[FDTYPE::HPWRITE];
    bool vmsplice_error = false;

    if (!inputs.empty())
    {
        // Prepare the input memory segments to map with vmsplice.
        size_t i = 0;
        iovec memsegs[inputs.size()];
        for (std::string &input : inputs)
        {
            memsegs[i].iov_base = input.data();
            memsegs[i].iov_len = input.length();
            i++;
        }

        // We use vmsplice to map (zero-copy) the inputs into the fd.
        if (vmsplice(writefd, memsegs, inputs.size(), 0) == -1)
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
 * Write the given input buffer into the write fd from the HP side.
 * @param fds Vector of fd list.
 * @param inputs Buffer to write into the HP write fd.
 */
int write_npl_iopipe(std::vector<int> &fds, std::list<std::string> &inputs)
{
    /**
     * npl inputs are feed into the contract in a binary protocol. It follows the following pattern
     * |**NPL version (1 byte)**|**Reserved (1 byte)**|**Length of the message (2 bytes)**|**Public key (4 bytes)**|**Npl message data**|
     * Length of the message is calculated without including public key length
     */
    const int writefd = fds[FDTYPE::HPWRITE];
    bool vmsplice_error = false;
    if (!inputs.empty())
    {
        int8_t total_memsegs = inputs.size() * 3;
        iovec memsegs[total_memsegs];
        size_t i = 0;
        for (auto &input : inputs)
        {
            int8_t pre_header_index = i * 3;
            int8_t pubkey_index = i * 3 + 1;
            int8_t msg_index = i * 3 + 2;

            // First binary representation of version, reserve and message length is constructed and feed it into
            // memory segment. Then the public key and at last the message data

            std::bitset<8> version(util::MIN_NPL_INPUT_VERSION);
            std::string stringified_version = version.to_string();

            // At the moment no data is inserted as reserve
            std::bitset<8> reserve(0);
            std::string stringified_reserve = reserve.to_string();

            //Get message container
            const fbschema::p2pmsg::Container *container = fbschema::p2pmsg::GetContainer(input.data());
            const flatbuffers::Vector<uint8_t> *container_content = container->content();

            std::bitset<16> msg_length(container_content->size());
            std::string stringified_msg_length = msg_length.to_string();

            stringified_version.append(stringified_reserve).append(stringified_msg_length);

            std::bitset<32> ver_res_msglen_bitset(stringified_version);
            std::int32_t numeric_pre_header = ver_res_msglen_bitset.to_ulong();
            memsegs[pre_header_index].iov_base = &numeric_pre_header;
            memsegs[pre_header_index].iov_len = 4;

            std::string_view msg_pubkey = fbschema::flatbuff_bytes_to_sv(container->pubkey());
            memsegs[pubkey_index].iov_base = reinterpret_cast<void *>(const_cast<char *>(msg_pubkey.data()));
            memsegs[pubkey_index].iov_len = msg_pubkey.size();

            memsegs[msg_index].iov_base = reinterpret_cast<void *>(const_cast<uint8_t *>(container_content->Data()));
            memsegs[msg_index].iov_len = container_content->size();

            i++;
        }

        if (vmsplice(writefd, memsegs, total_memsegs, 0) == -1)
            vmsplice_error = true;
    }
    // It's important that we DO NOT clear the input buffer string until the contract
    // process has actually read from the fd. Because the OS is just mapping our
    // input buffer memory portion into the fd, if we clear it now, the contract process
    // will get invaid bytes when reading the fd.

    // Close the writefd since we no longer need it.
    close(writefd);
    fds[FDTYPE::HPWRITE] = 0;

    return vmsplice_error ? -1 : 0;
}

/**
 * Common function to read and close SC output from the pipe and populate the output list.
 * @param fds Vector representing the pipes fd list.
 * @param output The buffer to place the read output.
 */
int read_iopipe(std::vector<int> &fds, std::string &output)
{
    // Read any data that have been written by the contract process
    // from the output pipe and store in the output buffer.
    // Outputs will be read by the consensus process later when it wishes so.

    const int readfd = fds[FDTYPE::HPREAD];
    int bytes_available = 0;
    ioctl(readfd, FIONREAD, &bytes_available);
    bool vmsplice_error = false;

    if (bytes_available > 0)
    {
        output.resize(bytes_available);

        // Populate the user output buffer with new data from the pipe.
        // We use vmsplice to map (zero-copy) the output from the fd into output bbuffer.
        iovec memsegs[1];
        memsegs[0].iov_base = output.data();
        memsegs[0].iov_len = bytes_available;

        if (vmsplice(readfd, memsegs, 1, 0) == -1)
            vmsplice_error = true;
    }

    // Close readfd fd on HP process side because we are done with contract process I/O.
    close(readfd);
    fds[FDTYPE::HPREAD] = 0;

    return vmsplice_error ? -1 : 0;
}

void close_unused_fds(const bool is_hp)
{
    close_unused_vectorfds(is_hp, hpscfds);

    close_unused_vectorfds(is_hp, nplfds);

    // Loop through user fds.
    for (auto &[pubkey, fds] : userfds)
        close_unused_vectorfds(is_hp, fds);

    // Loop through npl fds.
    // for (auto &[pubkey, fds] : nplfds)
    //     close_unused_vectorfds(is_hp, fds);
}

/**
 * Common function for closing unused fds based on which process this gets called from.
 * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
 * @param fds Vector of fds to close.
 */
void close_unused_vectorfds(const bool is_hp, std::vector<int> &fds)
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