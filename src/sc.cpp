#include "pchheader.hpp"
#include "conf.hpp"
#include "hplog.hpp"
#include "sc.hpp"
#include "hpfs/hpfs.hpp"

namespace sc
{
    /**
     * Executes the contract process and passes the specified context arguments.
     * @return 0 on successful process creation. -1 on failure or contract process is already running.
     */
    int execute_contract(execution_context &ctx)
    {
        // Start the hpfs rw session before starting the contract process.
        if (start_hpfs_rw_session(ctx) == -1)
            return -1;

        // Setup io pipes and feed all inputs to them.
        create_iopipes_for_fdmap(ctx.userfds, ctx.args.userbufs);

        if (!ctx.args.readonly)
        {
            create_iopipes(ctx.nplfds, !ctx.args.npl_messages.empty());
            create_iopipes(ctx.hpscfds, !ctx.args.hpscbufs.inputs.empty());
        }

        int ret = 0;

        LOG_DEBUG << "Starting contract process..." << (ctx.args.readonly ? " (rdonly)" : "");

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
            if (feed_inputs(ctx) == -1)
            {
                util::kill_process(pid, true);
                ctx.contract_pid = 0;
                goto failure;
            }

            // Wait for child process (contract process) to complete execution.
            const int presult = await_process_execution(ctx.contract_pid);
            ctx.contract_pid = 0;

            LOG_DEBUG << "Contract process ended." << (ctx.args.readonly ? " (rdonly)" : "");

            // Wait for the output collection thread to gracefully stop.
            ctx.output_fetcher_thread.join();

            if (presult != 0)
            {
                LOG_ERROR << "Contract process exited with non-normal status code: " << presult;
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

            const bool using_appbill = !ctx.args.readonly && !conf::cfg.appbill.empty();
            int len = conf::cfg.runtime_binexec_args.size() + 1;
            if (using_appbill)
                len += conf::cfg.runtime_appbill_args.size();

            // Fill process args.
            char *execv_args[len];
            int j = 0;
            if (using_appbill)
            {
                for (int i = 0; i < conf::cfg.runtime_appbill_args.size(); i++, j++)
                    execv_args[i] = conf::cfg.runtime_appbill_args[i].data();
            }

            for (int i = 0; i < conf::cfg.runtime_binexec_args.size(); i++, j++)
                execv_args[j] = conf::cfg.runtime_binexec_args[i].data();
            execv_args[len - 1] = NULL;

            chdir(ctx.args.state_dir.c_str());

            int ret = execv(execv_args[0], execv_args);
            std::cerr << errno << ": Contract process execv failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting contract process." << (ctx.args.readonly ? " (rdonly)" : "");
            goto failure;
        }

        goto success;
    failure:
        ret = -1;

    success:
        stop_hpfs_rw_session(ctx);
        cleanup_fdmap(ctx.userfds);
        if (!ctx.args.readonly)
        {
            cleanup_vectorfds(ctx.hpscfds);
            cleanup_vectorfds(ctx.nplfds);
        }

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
        if (hpfs::start_fs_session(ctx.hpfs_pid, ctx.args.state_dir, ctx.args.readonly ? "ro" : "rw", true) == -1)
            return -1;

        LOG_DEBUG << "hpfs session started. pid:" << ctx.hpfs_pid << (ctx.args.readonly ? " (rdonly)" : "");
        return 0;
    }

    /**
     * Stops the hpfs state filesystem.
     */
    int stop_hpfs_rw_session(execution_context &ctx)
    {
        // Read the root hash if not in readonly mode.
        if (!ctx.args.readonly && hpfs::get_hash(ctx.args.post_execution_state_hash, ctx.args.state_dir, "/") < 1)
            return -1;

        LOG_DEBUG << "Stopping hpfs session... pid:" << ctx.hpfs_pid << (ctx.args.readonly ? " (rdonly)" : "");

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
     *   "readonly": <true|false>,
     *   "lcl": "<this node's last closed ledger seq no. and hash in hex>", (eg: 169-a1d82eb4c9ed005ec2c4f4f82b6f0c2fd7543d66b1a0f6b8e58ae670b3e2bcfb)
     *   "hpfd": [fd0, fd1],
     *   "nplfd":[fd0, fd1],
     *   "usrfd":{ "<pkhex>":[fd0, fd1], ... },
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
           << ",\"readonly\":" << (ctx.args.readonly ? "true" : "false");

        if (!ctx.args.readonly)
        {
            os << ",\"lcl\":\"" << ctx.args.lcl
               << "\",\"hpfd\":[" << ctx.hpscfds[FDTYPE::SCREAD] << "," << ctx.hpscfds[FDTYPE::SCWRITE]
               << "],\"nplfd\":[" << ctx.nplfds[FDTYPE::SCREAD] << "," << ctx.nplfds[FDTYPE::SCWRITE] << "]";
        }

        os << ",\"usrfd\":{";

        fdmap_json_to_stream(ctx.userfds, os);

        os << "},\"unl\":[";

        for (auto nodepk = conf::cfg.unl.begin(); nodepk != conf::cfg.unl.end(); nodepk++)
        {
            if (nodepk != conf::cfg.unl.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary nodepk into hex.
            std::string pubkeyhex;
            util::bin2hex(
                pubkeyhex,
                reinterpret_cast<const unsigned char *>((*nodepk).data()) + 1,
                (*nodepk).length() - 1);

            os << "\"" << pubkeyhex << "\"";
        }

        os << "]}";

        // Get the json string that should be written to contract input pipe.
        const std::string json = os.str();

        // Establish contract input pipe.
        int stdinpipe[2];
        if (pipe(stdinpipe) == -1)
        {
            LOG_ERROR << errno << ": Failed to create pipe to the contract process.";
            return -1;
        }

        // Redirect pipe read-end to the contract std input so the
        // contract process can read from our pipe.
        dup2(stdinpipe[0], STDIN_FILENO);
        close(stdinpipe[0]);

        // Write the json message and close write fd.
        if (write(stdinpipe[1], json.data(), json.size()) == -1)
        {
            LOG_ERROR << errno << ": Failed to write to stdin of contract process.";
            return -1;
        }
        close(stdinpipe[1]);

        return 0;
    }

    int feed_inputs(execution_context &ctx)
    {
        // Write any input messages to hp->sc pipe.
        if (!ctx.args.readonly && write_contract_hp_inputs(ctx) == -1)
            return -1;

        // Write any NPL messages to contract.
        if (!ctx.args.readonly && write_npl_messages(ctx) == -1)
            return -1;

        // Write any verified (consensus-reached) user inputs to user pipes.
        if (write_contract_fdmap_inputs(ctx.userfds, ctx.args.userbufs) == -1)
        {
            LOG_ERROR << "Failed to write user inputs to contract.";
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

            const int hpsc_npl_res = ctx.args.readonly ? 0 : read_contract_hp_npl_outputs(ctx);
            if (hpsc_npl_res == -1)
                return -1;

            const int user_res = read_contract_fdmap_outputs(ctx.userfds, ctx.args.userbufs);
            if (user_res == -1)
            {
                LOG_ERROR << "Error reading user outputs from the contract.";
                return -1;
            }

            // If no bytes were read after contract finished execution, exit the read loop.
            if (hpsc_npl_res == 0 && user_res == 0 && ctx.contract_pid == 0)
                break;

            util::sleep(20);
        }

        LOG_DEBUG << "Contract outputs collected.";
        return 0;
    }

    /**
     * Writes any hp input messages to the contract.
     */
    int write_contract_hp_inputs(execution_context &ctx)
    {
        if (write_iopipe(ctx.hpscfds, ctx.args.hpscbufs.inputs) == -1)
        {
            LOG_ERROR << "Error writing HP inputs to SC";
            return -1;
        }

        return 0;
    }

    /**
     * Write npl messages to the contract.
     */
    int write_npl_messages(execution_context &ctx)
    {
        /**
         * npl inputs are feed into the contract in a binary protocol. It follows the following pattern
         * |**NPL version (1 byte)**|**Reserved (1 byte)**|**Length of the message (2 bytes)**|**Public key (32 bytes)**|**Npl message data**|
         * Length of the message is calculated without including public key length
         */
        const int writefd = ctx.nplfds[FDTYPE::HPWRITE];
        if (writefd == -1)
            return 0;

        bool write_error = false;
        if (!ctx.args.npl_messages.empty())
        {
            const size_t total_memsegs = ctx.args.npl_messages.size() * 3;
            iovec memsegs[total_memsegs];
            size_t i = 0;
            for (const auto &npl_msg : ctx.args.npl_messages)
            {
                const uint8_t pre_header_index = i * 3;
                const uint8_t pubkey_index = pre_header_index + 1;
                const uint8_t msg_index = pre_header_index + 2;

                const uint16_t msg_len = npl_msg.data.size();

                // Header is |version(1byte)|reserve(1byte)|msg length(2bytes big endian)|
                uint8_t header[4];
                header[0] = util::MIN_NPL_INPUT_VERSION;

                // Store msg length in big endian.
                header[2] = msg_len << 8;
                header[3] = msg_len;

                memsegs[pre_header_index].iov_base = header;
                memsegs[pre_header_index].iov_len = sizeof(header);

                // Pubkey without the key type prefix.
                memsegs[pubkey_index].iov_base = reinterpret_cast<void *>(const_cast<char *>(npl_msg.pubkey.data() + 1));
                memsegs[pubkey_index].iov_len = npl_msg.pubkey.size() - 1;

                memsegs[msg_index].iov_base = reinterpret_cast<void *>(const_cast<char *>(npl_msg.data.data()));
                memsegs[msg_index].iov_len = msg_len;

                i++;
            }

            if (writev(writefd, memsegs, total_memsegs) == -1)
                write_error = true;

            ctx.args.npl_messages.clear();
        }

        // Close the writefd since we no longer need it.
        close(writefd);
        ctx.nplfds[FDTYPE::HPWRITE] = -1;

        return write_error ? -1 : 0;
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
            LOG_ERROR << "Error reading HP output from the contract.";
            return -1;
        }

        const int npl_res = read_iopipe(ctx.nplfds, ctx.args.npl_output);
        if (npl_res == -1)
        {
            LOG_ERROR << "Error reading NPL output from the contract.";
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
                reinterpret_cast<const unsigned char *>(pubkey.data()) + 1,
                pubkey.length() - 1);

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
            if (create_iopipes(fds, !buflist.inputs.empty()) == -1)
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
            if (write_iopipe(fdmap[pubkey], buflist.inputs) == -1)
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
     * @param create_inpipe Whether to create the input pipe from HP to SC.
     */
    int create_iopipes(std::vector<int> &fds, const bool create_inpipe)
    {
        int inpipe[2] = {-1, -1};
        if (create_inpipe && pipe(inpipe) == -1)
            return -1;

        int outpipe[2] = {-1, -1};
        if (pipe(outpipe) == -1)
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
        if (!ctx.args.readonly)
        {
            close_unused_vectorfds(is_hp, ctx.hpscfds);
            close_unused_vectorfds(is_hp, ctx.nplfds);
        }

        // Loop through user fds.
        for (auto &[pubkey, fds] : ctx.userfds)
            close_unused_vectorfds(is_hp, fds);
    }

    /**
     * Common function for closing unused fds based on which process this gets called from.
     * This also marks active fds with O_CLOEXEC for close-on-exec behaviour.
     * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
     * @param fds Vector of fds to close.
     */
    void close_unused_vectorfds(const bool is_hp, std::vector<int> &fds)
    {
        for (int fd_type = 0; fd_type <= 3; fd_type++)
        {
            const int fd = fds[fd_type];
            if (fd != -1)
            {
                if ((is_hp && (fd_type == FDTYPE::SCREAD || fd_type == FDTYPE::SCWRITE)) ||
                    (!is_hp && (fd_type == FDTYPE::HPREAD || fd_type == FDTYPE::HPWRITE)))
                {
                    close(fd);
                    fds[fd_type] = -1;
                }
                else if (is_hp && (fd_type == FDTYPE::HPREAD || fd_type == FDTYPE::HPWRITE))
                {
                    // The fd must be kept open in HP process. But we must
                    // mark it to close on exec in a potential forked process.
                    int flags = fcntl(fd, F_GETFD, NULL);
                    flags |= FD_CLOEXEC;
                    fcntl(fd, F_SETFD, flags);
                }
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
        args.npl_messages.clear();
        args.npl_output.clear();
        args.time = 0;
        args.lcl.clear();
        args.post_execution_state_hash = hpfs::h32_empty;
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
