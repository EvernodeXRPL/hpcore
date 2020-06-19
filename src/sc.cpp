#include "pchheader.hpp"
#include "conf.hpp"
#include "hplog.hpp"
#include "fbschema/common_helpers.hpp"
#include "fbschema/p2pmsg_container_generated.h"
#include "fbschema/p2pmsg_content_generated.h"
#include "sc.hpp"
#include "hpfs/hpfs.hpp"

namespace sc
{
    /**
 * Executes the contract process and passes the specified context arguments.
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
    int execute_contract(execution_context &ctx, hpfs::h32 &state_hash)
    {
        // Start the hpfs rw session before starting the contract process.
        if (start_hpfs_rw_session(ctx) != 0)
            return -1;

        // Setup io pipes and feed all inputs to them.
        create_iopipes_for_fdmap(ctx.userfds, ctx.args.userbufs);
        create_iopipes(ctx.nplfds, !ctx.args.nplbufs.inputs.empty());
        create_iopipes(ctx.hpscfds, !ctx.args.hpscbufs.inputs.empty());

        int ret = 0;
        const pid_t pid = fork();
        if (pid > 0)
        {
            // HotPocket process.
            ctx.contract_pid = pid;

            // Close all fds unused by HP process.
            close_unused_fds(ctx, true);

            // Start the contract output collection thread.
            ctx.output_fetcher_thread = std::thread(fetch_outputs, std::ref(ctx));

            // Write the inputs into the contract process.
            if (feed_inputs(ctx) != 0)
                goto failure;

            // Wait for child process (contract process) to complete execution.
            const int presult = await_process_execution(ctx.contract_pid);
            ctx.contract_pid = 0;

            LOG_DBG << "Contract process ended.";

            // Wait for the output collection thread to gracefully stop.
            ctx.output_fetcher_thread.join();

            if (presult != 0)
            {
                LOG_ERR << "Contract process exited with non-normal status code: " << presult;
                goto failure;
            }
        }
        else if (pid == 0)
        {
            // Contract process.
            util::unmask_signal();

            // Set up the process environment and overlay the contract binary program with execv().

            // Close all fds unused by SC process.
            close_unused_fds(ctx, false);

            // Write the contract input message from HotPocket to the stdin (0) of the contract process.
            write_contract_args(ctx);

            LOG_DBG << "Starting contract process...";

            const bool using_appbill = !conf::cfg.appbill.empty();
            int len = conf::cfg.runtime_binexec_args.size() + 1;
            if (using_appbill)
                len += conf::cfg.runtime_appbill_args.size();

            // Fill process args.
            char *execv_args[len];
            int j = 0;
            if (using_appbill)
                for (int i = 0; i < conf::cfg.runtime_appbill_args.size(); i++, j++)
                    execv_args[i] = conf::cfg.runtime_appbill_args[i].data();

            for (int i = 0; i < conf::cfg.runtime_binexec_args.size(); i++, j++)
                execv_args[j] = conf::cfg.runtime_binexec_args[i].data();
            execv_args[len - 1] = NULL;

            chdir(conf::ctx.state_rw_dir.c_str());

            int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": Contract process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERR << "fork() failed when starting contract process.";
            goto failure;
        }

        goto success;
    failure:
        ret = -1;

    success:
        stop_hpfs_rw_session(ctx, state_hash);
        cleanup_fdmap(ctx.userfds);
        cleanup_vectorfds(ctx.hpscfds);
        cleanup_vectorfds(ctx.nplfds);

        return ret;
    }

    /**
 * Blocks the calling thread until the specified process completed exeution (if running).
 * @return 0 if process exited normally or exit code of process if abnormally exited.
 */
    int await_process_execution(pid_t pid)
    {
        if (pid > 0)
        {
            int scstatus;
            waitpid(pid, &scstatus, 0);
            if (!WIFEXITED(scstatus))
                return WEXITSTATUS(scstatus);
        }
        return 0;
    }

    /**
 * Starts the hpfs read/write state filesystem.
 */
    int start_hpfs_rw_session(execution_context &ctx)
    {
        if (hpfs::start_fs_session(ctx.hpfs_pid, conf::ctx.state_rw_dir, "rw", true) == -1)
            return -1;

        LOG_DBG << "hpfs rw session started. pid:" << ctx.hpfs_pid;
    }

    /**
 * Stops the hpfs state filesystem.
 */
    int stop_hpfs_rw_session(execution_context &ctx, hpfs::h32 &state_hash)
    {
        // Read the root hash.
        if (hpfs::get_hash(state_hash, conf::ctx.state_rw_dir, "/") == -1)
            return -1;

        LOG_DBG << "Stopping hpfs rw session... pid:" << ctx.hpfs_pid;
        if (util::kill_process(ctx.hpfs_pid, true) == -1)
            return -1;

        ctx.hpfs_pid = 0;
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
    int write_contract_args(const execution_context &ctx)
    {
        // Populate the json string with contract args.
        // We don't use a JSON parser here because it's lightweight to contrstuct the
        // json string manually.

        std::ostringstream os;
        os << "{\"version\":\"" << util::HP_VERSION
           << "\",\"pubkey\":\"" << conf::cfg.pubkeyhex
           << "\",\"ts\":" << ctx.args.time
           << ",\"hpfd\":[" << ctx.hpscfds[FDTYPE::SCREAD] << "," << ctx.hpscfds[FDTYPE::SCWRITE]
           << "],\"usrfd\":{";

        fdmap_json_to_stream(ctx.userfds, os);

        os << "},\"nplfd\":[" << ctx.nplfds[FDTYPE::SCREAD] << "," << ctx.nplfds[FDTYPE::SCWRITE]
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

    int feed_inputs(execution_context &ctx)
    {
        // Write any hp or npl input messages to hp->sc and npl->sc pipe.
        if (write_contract_hp_npl_inputs(ctx) != 0)
        {
            return -1;
        }

        // Write any verified (consensus-reached) user inputs to user pipes.
        if (write_contract_fdmap_inputs(ctx.userfds, ctx.args.userbufs) != 0)
        {
            LOG_ERR << "Failed to write user inputs to contract.";
            return -1;
        }

        return 0;
    }

    int fetch_outputs(execution_context &ctx)
    {
        util::mask_signal();

        while (true)
        {
            if (ctx.should_stop)
                break;

            const int hpsc_npl_res = read_contract_hp_npl_outputs(ctx);
            if (hpsc_npl_res == -1)
                return -1;

            const int user_res = read_contract_fdmap_outputs(ctx.userfds, ctx.args.userbufs);
            if (user_res == -1)
            {
                LOG_ERR << "Error reading user outputs from the contract.";
                return -1;
            }

            // If no bytes were read after contract finished execution, exit the read loop.
            if (hpsc_npl_res == 0 && user_res == 0 && ctx.contract_pid == 0)
                break;

            util::sleep(20);
        }

        LOG_DBG << "Contract outputs collected.\n";
        return 0;
    }

    /**
 * Writes any hp input messages to the contract.
 */
    int write_contract_hp_npl_inputs(execution_context &ctx)
    {
        if (write_iopipe(ctx.hpscfds, ctx.args.hpscbufs.inputs) != 0)
        {
            LOG_ERR << "Error writing HP inputs to SC";
            return -1;
        }

        if (write_npl_iopipe(ctx.nplfds, ctx.args.nplbufs.inputs) != 0)
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
 * @return 0 if no bytes were read. 1 if bytes were read. -1 on failure.
 */
    int read_contract_hp_npl_outputs(execution_context &ctx)
    {
        const int hpsc_res = read_iopipe(ctx.hpscfds, ctx.args.hpscbufs.output);
        if (hpsc_res == -1)
        {
            LOG_ERR << "Error reading HP output from the contract.";
            return -1;
        }

        const int npl_res = read_iopipe(ctx.nplfds, ctx.args.nplbufs.output);
        if (npl_res == -1)
        {
            LOG_ERR << "Error reading NPL output from the contract.";
            return -1;
        }

        return (hpsc_res == 0 && npl_res == 0) ? 0 : 1;
    }

    /**
 * Common helper function to write json output of fdmap to given ostream.
 * @param fdmap Any pubkey->fdlist map. (eg. ctx.userfds, ctx.nplfds)
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
            if (create_iopipes(fds, !buflist.inputs.empty()) != 0)
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
 * @return 0 if no bytes were read. 1 if bytes were read. -1 on failure.
 */
    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
    {
        bool bytes_read = false;
        for (auto &[pubkey, bufpair] : bufmap)
        {
            // Get fds for the pubkey.
            std::vector<int> &fds = fdmap[pubkey];

            const int res = read_iopipe(fds, bufpair.output);
            if (res == -1)
                return -1;

            if (res > 0)
                bytes_read = true;
        }

        return bytes_read ? 1 : 0;
    }

    /**
 * Common function to close any open fds in the map after an error.
 * @param fdmap Any pubkey->fdlist map. (eg. ctx.userfds, ctx.nplfds)
 */
    void cleanup_fdmap(contract_fdmap_t &fdmap)
    {
        for (auto &[pubkey, fds] : fdmap)
            cleanup_vectorfds(fds);

        fdmap.clear();
    }

    /**
 * Common function to create a pair of pipes (Hp->SC, SC->HP).
 * @param fds Vector to populate fd list.
 * @param inputbuffer Buffer to write into the HP write fd.
 * @param create_inpipe Whether to create the input pipe from HP to SC.
 */
    int create_iopipes(std::vector<int> &fds, const bool create_inpipe)
    {
        int inpipe[2] = {-1, -1};
        if (create_inpipe && pipe(inpipe) != 0)
            return -1;

        int outpipe[2] = {-1, -1};
        if (pipe(outpipe) != 0)
        {
            if (create_inpipe)
            {
                // Close the earlier created pipe.
                close(inpipe[0]);
                close(inpipe[1]);
            }
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
        if (writefd == -1)
            return 0;

        bool write_error = false;

        if (!inputs.empty())
        {
            // Prepare the input memory segments to write with wrtiev.
            size_t i = 0;
            iovec memsegs[inputs.size()];
            for (std::string &input : inputs)
            {
                memsegs[i].iov_base = input.data();
                memsegs[i].iov_len = input.length();
                i++;
            }

            if (writev(writefd, memsegs, inputs.size()) == -1)
                write_error = true;

            inputs.clear();
        }

        // Close the writefd since we no longer need it.
        close(writefd);
        fds[FDTYPE::HPWRITE] = -1;

        return write_error ? -1 : 0;
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
        if (writefd == -1)
            return 0;

        bool write_error = false;
        if (!inputs.empty())
        {
            int8_t total_memsegs = inputs.size() * 3;
            iovec memsegs[total_memsegs];
            size_t i = 0;
            for (auto &input : inputs)
            {
                int8_t pre_header_index = i * 3;
                int8_t pubkey_index = pre_header_index + 1;
                int8_t msg_index = pre_header_index + 2;

                // First binary representation of version, reserve and message length is constructed and feed it into
                // memory segment. Then the public key and at last the message data

                // At the moment no data is inserted as reserve
                uint8_t reserve = 0;

                //Get message container
                const fbschema::p2pmsg::Container *container = fbschema::p2pmsg::GetContainer(input.data());
                const flatbuffers::Vector<uint8_t> *container_content = container->content();

                uint16_t msg_length = container_content->size();

                /**
             * Pre header is constructed using bit shifting. This will generate a bit pattern as explain in the example below 
             * version = 00000001
             * reserve = 00000000
             * msg_length = 0000000010001101
             * pre_header = 00000001000000000000000010001101
             */
                uint32_t pre_header = util::MIN_NPL_INPUT_VERSION;
                pre_header = pre_header << 8;
                pre_header += reserve;

                pre_header = pre_header << 16;
                pre_header += msg_length;
                memsegs[pre_header_index].iov_base = &pre_header;
                memsegs[pre_header_index].iov_len = 4;

                std::string_view msg_pubkey = fbschema::flatbuff_bytes_to_sv(container->pubkey());
                memsegs[pubkey_index].iov_base = reinterpret_cast<void *>(const_cast<char *>(msg_pubkey.data()));
                memsegs[pubkey_index].iov_len = msg_pubkey.size();

                memsegs[msg_index].iov_base = reinterpret_cast<void *>(const_cast<uint8_t *>(container_content->Data()));
                memsegs[msg_index].iov_len = container_content->size();

                i++;
            }

            if (writev(writefd, memsegs, total_memsegs) == -1)
                write_error = true;

            inputs.clear();
        }

        // Close the writefd since we no longer need it.
        close(writefd);
        fds[FDTYPE::HPWRITE] = -1;

        return write_error ? -1 : 0;
    }

    /**
 * Common function to read buffered output from the pipe and populate the output list.
 * @param fds Vector representing the pipes fd list.
 * @param output The buffer to place the read output.
 * @return -1 on error. Otherwise no. of bytes read.
 */
    int read_iopipe(std::vector<int> &fds, std::string &output)
    {
        // Read any available data that have been written by the contract process
        // from the output pipe and store in the output buffer.
        // Outputs will be read by the consensus process later when it wishes so.

        const int readfd = fds[FDTYPE::HPREAD];
        if (readfd == -1)
            return 0;

        bool read_error = false;
        size_t available_bytes = 0;
        if (ioctl(readfd, FIONREAD, &available_bytes) != -1)
        {
            if (available_bytes == 0)
                return 0;

            const size_t current_size = output.size();
            output.resize(current_size + available_bytes);
            const int res = read(readfd, output.data() + current_size, available_bytes);

            if (res >= 0)
            {
                if (res == 0) // EOF
                {
                    close(readfd);
                    fds[FDTYPE::HPREAD] = -1;
                }
                return res;
            }
        }

        close(readfd);
        fds[FDTYPE::HPREAD] = -1;
        return -1;
    }

    void close_unused_fds(execution_context &ctx, const bool is_hp)
    {
        close_unused_vectorfds(is_hp, ctx.hpscfds);

        close_unused_vectorfds(is_hp, ctx.nplfds);

        // Loop through user fds.
        for (auto &[pubkey, fds] : ctx.userfds)
            close_unused_vectorfds(is_hp, fds);
    }

    /**
 * Common function for closing unused fds based on which process this gets called from.
 * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
 * @param fds Vector of fds to close.
 */
    void close_unused_vectorfds(const bool is_hp, std::vector<int> &fds)
    {
        const int fdtypes_to_close[2] = {
            is_hp ? FDTYPE::SCREAD : FDTYPE::HPREAD,
            is_hp ? FDTYPE::SCWRITE : FDTYPE::HPWRITE,
        };

        for (const int fdtype : fdtypes_to_close)
        {
            const int fd = fds[fdtype];
            if (fd != -1)
            {
                close(fd);
                fds[fdtype] = -1;
            }
        }
    }

    /**
 * Closes all fds in a vector fd set.
 */
    void cleanup_vectorfds(std::vector<int> &fds)
    {
        for (int i = 0; i < fds.size(); i++)
        {
            if (fds[i] != -1)
            {
                close(fds[i]);
                fds[i] = -1;
            }
        }

        fds.clear();
    }

    void clear_args(contract_execution_args &args)
    {
        args.userbufs.clear();
        args.hpscbufs.inputs.clear();
        args.hpscbufs.output.clear();
        args.nplbufs.inputs.clear();
        args.nplbufs.output.clear();
        args.time = 0;
    }

    /**
 * Cleanup any running processes for the specified execution context.
 */
    void stop(execution_context &ctx)
    {
        ctx.should_stop = true;

        if (ctx.contract_pid > 0)
            util::kill_process(ctx.contract_pid, true);

        if (ctx.hpfs_pid > 0)
            util::kill_process(ctx.hpfs_pid, true);

        if (ctx.output_fetcher_thread.joinable())
            ctx.output_fetcher_thread.join();
    }

} // namespace sc
