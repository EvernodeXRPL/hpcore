#include "pchheader.hpp"
#include "conf.hpp"
#include "consensus.hpp"
#include "hplog.hpp"
#include "ledger.hpp"
#include "sc.hpp"
#include "hpfs/hpfs.hpp"
#include "msg/fbuf/p2pmsg_helpers.hpp"

namespace sc
{
    const int MAX_SEQ_PACKET_SIZE = 128 * 1024;
    bool init_success = false;

    // We maintain two hpfs global processes for merging and rw sessions.
    pid_t hpfs_merge_pid = 0;
    pid_t hpfs_rw_pid = 0;

    /**
     * Performs system startup activitites related to smart contract execution.
     */
    int init()
    {
        if (hpfs::start_merge_process(hpfs_merge_pid) == -1)
            return -1;

        if (hpfs::start_ro_rw_process(hpfs_rw_pid, conf::ctx.state_rw_dir, false, true, false) == -1)
        {
            // Stop the merge process in case of failure.
            util::kill_process(hpfs_merge_pid, true);
            return -1;
        }

        init_success = true;
        return 0;
    }

    /**
     * Performs global cleanup related to smart contract execution.
     */
    void deinit()
    {
        if (init_success)
        {
            LOG_DEBUG << "Stopping hpfs rw process... pid:" << hpfs_rw_pid;
            if (hpfs_rw_pid > 0 && util::kill_process(hpfs_rw_pid, true) == 0)
                LOG_INFO << "Stopped hpfs rw process.";

            LOG_DEBUG << "Stopping hpfs merge process... pid:" << hpfs_merge_pid;
            if (hpfs_merge_pid > 0 && util::kill_process(hpfs_merge_pid, true) == 0)
                LOG_INFO << "Stopped hpfs merge process.";
        }
    }

    /**
     * Executes the contract process and passes the specified context arguments.
     * @return 0 on successful process creation. -1 on failure or contract process is already running.
     */
    int execute_contract(execution_context &ctx)
    {
        // Start the hpfs rw session before starting the contract process.
        if (start_hpfs_session(ctx) == -1)
            return -1;

        // Setup io sockets and feed all inputs to them.
        create_iosockets_for_fdmap(ctx.userfds, ctx.args.userbufs);

        if (!ctx.args.readonly)
        {
            // create sequential packet sockets for npl and hp messages.
            create_iosockets(ctx.nplfds, SOCK_SEQPACKET);
            create_iosockets(ctx.hpscfds, SOCK_SEQPACKET);
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
            ctx.contract_io_thread = std::thread(handle_contract_io, std::ref(ctx));

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

            // There could be 2 reasons for the contract to end; the contract voluntary finished execution or
            // it was killed due to Hot Pocket shutting down.

            // Wait for the i/o thread to gracefully stop if this is voluntary contract termination.
            // 'ctx.should_stop' indicates Hot Pocket is shutting down. If that's the case ouput collection thread
            // is joined by the deinit logic.
            if (!ctx.should_stop && ctx.contract_io_thread.joinable())
                ctx.contract_io_thread.join();

            if (presult != 0)
            {
                LOG_ERROR << "Contract process exited with non-normal status code: " << presult;
                goto failure;
            }
        }
        else if (pid == 0)
        {
            // Contract process.
            util::fork_detach();

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
        if (stop_hpfs_session(ctx) == -1)
            ret = -1;

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
            int scstatus = 0;
            waitpid(pid, &scstatus, 0);
            if (!WIFEXITED(scstatus))
                return WEXITSTATUS(scstatus);
        }
        return 0;
    }

    /**
     * Starts the hpfs read/write state filesystem.
     */
    int start_hpfs_session(execution_context &ctx)
    {
        // In readonly mode, we must start the hpfs process first.
        // In RW mode, there is a global hpfs RW process so we only need to create an fs session.
        if (ctx.args.readonly)
        {
            if (hpfs::start_ro_rw_process(ctx.hpfs_pid, ctx.args.state_dir, true, false, false) == -1)
                return -1;
        }
        else
        {
            ctx.hpfs_pid = hpfs_rw_pid;
        }

        if (hpfs::start_fs_session(ctx.args.state_dir) == -1)
            return -1;

        return 0;
    }

    /**
     * Stops the hpfs state filesystem.
     */
    int stop_hpfs_session(execution_context &ctx)
    {
        int result = 0;
        // Read the root hash if not in readonly mode.
        if (!ctx.args.readonly && hpfs::get_hash(ctx.args.post_execution_state_hash, ctx.args.state_dir, "/") < 1)
            result = -1;

        LOG_DEBUG << "Stopping hpfs contract session..." << (ctx.args.readonly ? " (rdonly)" : "");

        if (hpfs::stop_fs_session(ctx.args.state_dir) == -1)
            return -1;

        // In readonly mode, we must also stop the hpfs process itself after sopping the session.
        // In RW mode, we only need to stop the fs session and let the process keep running.
        if (ctx.args.readonly && util::kill_process(ctx.hpfs_pid, true) == -1)
            result = -1;

        ctx.hpfs_pid = 0;
        return result;
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
               << "\",\"hpfd\":" << ctx.hpscfds[SOCKETFDTYPE::SCREADWRITE]
               << ",\"nplfd\":" << ctx.nplfds[SOCKETFDTYPE::SCREADWRITE];
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
            close(stdinpipe[1]);
            LOG_ERROR << errno << ": Failed to write to stdin of contract process.";
            return -1;
        }
        close(stdinpipe[1]);

        return 0;
    }

    int feed_inputs(execution_context &ctx)
    {
        // Write any input messages to hp->sc socket.
        if (!ctx.args.readonly && write_contract_hp_inputs(ctx) == -1)
        {
            LOG_ERROR << "Error when writing contract hp inputs.";
            return -1;
        }

        // Write any user inputs to user sockets.
        if (write_contract_fdmap_inputs(ctx.userfds, ctx.args.userbufs) == -1)
        {
            LOG_ERROR << "Failed to write user inputs to contract.";
            return -1;
        }

        return 0;
    }

    /**
     * Collect contract outputs and feed npl messages while contract is running.
     * @param ctx Contract execution context.
     * @return Returns -1 if the operation fails otherwise 0.
    */
    int handle_contract_io(execution_context &ctx)
    {
        util::mask_signal();

        while (true)
        {
            if (ctx.should_stop)
                break;

            const int hpsc_res = ctx.args.readonly ? 0 : read_contract_hp_outputs(ctx);
            if (hpsc_res == -1)
                return -1;

            const int npl_read_res = ctx.args.readonly ? 0 : read_contract_npl_outputs(ctx);
            if (npl_read_res == -1)
                return -1;

            const int npl_write_res = ctx.args.readonly ? 0 : write_npl_messages(ctx);
            if (npl_write_res == -1)
                return -1;

            const int user_res = read_contract_fdmap_outputs(ctx.userfds, ctx.args.userbufs, ctx.args.user_stream_utils);
            if (user_res == -1)
            {
                LOG_ERROR << "Error reading user outputs from the contract.";
                return -1;
            }

            // If no bytes were read after contract finished execution, exit the read loop.
            if (hpsc_res == 0 && npl_read_res == 0 && user_res == 0 && ctx.contract_pid == 0)
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
        if (write_iosocket_seq_packet(ctx.hpscfds, ctx.args.hpscbufs.inputs, false) == -1)
        {
            LOG_ERROR << "Error writing HP inputs to SC";
            return -1;
        }

        return 0;
    }

    /**
     * Write npl messages to the contract.
     * @param ctx Contract execution context.
     * @return Returns -1 when fails otherwise 0.
     */
    int write_npl_messages(execution_context &ctx)
    {
        /**
         * npl inputs are feed into the contract as sequence packets. It first sends the pubkey and then
         * the data.
         */
        const int writefd = ctx.nplfds[SOCKETFDTYPE::HPREADWRITE];

        if (writefd == -1)
            return 0;

        // Dequeue the next npl message from the queue.
        // Check the lcl against the latest lcl.
        p2p::npl_message npl_msg;
        if (ctx.args.npl_messages.try_dequeue(npl_msg))
        {
            if (npl_msg.lcl == ledger::ctx.get_lcl())
            {
                // Writing the public key to the contract's fd.
                if (write(writefd, npl_msg.pubkey.data(), npl_msg.pubkey.size()) == -1)
                    return -1;
                // Writing the message to the contract's fd.
                if (write(writefd, npl_msg.data.data(), npl_msg.data.size()) == -1)
                    return -1;
            }
            else
            {
                LOG_DEBUG << "NPL message dropped due to lcl mismatch.";
            }
        }

        return 0;
    }

    /**
     * Read all HP output messages produced by the contract process and store them in
     * the buffer for later processing.
     * 
     * @return 0 if no bytes were read. 1 if bytes were read. -1 on failure.
     */
    int read_contract_hp_outputs(execution_context &ctx)
    {
        std::string output;
        const int hpsc_res = read_iosocket_seq_packet(ctx.hpscfds, output);
        if (hpsc_res == -1)
        {
            LOG_ERROR << "Error reading HP output from the contract.";
            return -1;
        }
        else if (hpsc_res > 0)
        {
            ctx.args.hpscbufs.outputs.push_back(output);
        }

        return (hpsc_res == 0) ? 0 : 1;
    }

    /**
     * Read all NPL output messages produced by the contract process and broadcast them.
     * @param ctx contract execution context.
     * @return 0 if no bytes were read. 1 if bytes were read. -1 on failure.
     */
    int read_contract_npl_outputs(execution_context &ctx)
    {
        std::string output;
        const int npl_res = read_iosocket_seq_packet(ctx.nplfds, output);

        if (npl_res == -1)
        {
            LOG_ERROR << "Error reading NPL output from the contract.";
            return -1;
        }
        else if (npl_res > 0)
        {
            // Broadcast npl messages once contract npl output is collected.
            broadcast_npl_output(output);
        }

        return (npl_res == 0) ? 0 : 1;
    }

    /**
     * Broadcast npl messages to peers.
     * @param output Npl message to be broadcasted.
    */
    void broadcast_npl_output(std::string_view output)
    {
        if (!output.empty())
        {
            flatbuffers::FlatBufferBuilder fbuf(1024);
            msg::fbuf::p2pmsg::create_msg_from_npl_output(fbuf, output, ledger::ctx.get_lcl());
            p2p::broadcast_message(fbuf, true);
        }
    }

    /**
     * Common helper function to write json output of fdmap to given ostream.
     * @param fdmap Any pubkey->fdlist map. (eg. ctx.userfds)
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
            os << "\"" << pubkeyhex << "\":"
               << itr->second[SOCKETFDTYPE::SCREADWRITE];
        }
    }

    /**
     * Creates io sockets for all pubkeys specified in bufmap.
     * @param fdmap A map which has public key and a vector<int> as fd list for that public key.
     * @param bufmap A map which has a public key and input/output buffer lists for that public key.
     * @return 0 on success. -1 on failure.
     */
    int create_iosockets_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
    {
        for (auto &[pubkey, buflist] : bufmap)
        {
            std::vector<int> fds = std::vector<int>();
            if (create_iosockets(fds, SOCK_STREAM) == -1)
                return -1;

            fdmap.emplace(pubkey, std::move(fds));
        }

        return 0;
    }

    /**
     * Common function to create the sockets and write buffer inputs to the fdmap.
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
            if (write_iosocket_stream(fdmap[pubkey], buflist.inputs, true) == -1)
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
     * @param user_stream_utils A map which has a public key and stream util variables for that public key.
     * @return 0 if no bytes were read. 1 if bytes were read. -1 on failure.
     */
    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap, contract_utilmap_t &user_stream_utils)
    {
        bool bytes_read = false;
        for (auto &[pubkey, bufpair] : bufmap)
        {
            // Get fds for the pubkey.
            std::string output;
            std::vector<int> &fds = fdmap[pubkey];
            contract_user_stream_utils &stream_util = user_stream_utils[pubkey];
            const int res = read_iosocket_stream(fds, output);

            if (res > 0)
            {
                int pos = 0;
                while (pos < res)
                {
                    if (stream_util.stream_msg_length == -1)
                    {
                        stream_util.stream_msg_length = output.at(pos + 3) | (output.at(pos + 2) << 24) | (output.at(pos + 1) << 16) | (output.at(pos) << 8);
                        pos += 4;
                    }
                    int possible_read_len;
                    if (((res - pos) - stream_util.stream_msg_length) >= 0)
                    {
                        // Can finish reading a full message.
                        possible_read_len = stream_util.stream_msg_length;
                        stream_util.stream_msg_length = -1;
                    }
                    else
                    {
                        // Only parcial message is recieved.
                        possible_read_len = res - pos;
                        stream_util.stream_msg_length -= possible_read_len;
                    }
                    std::string msgBuf = output.substr(pos, possible_read_len);
                    pos += possible_read_len;
                    stream_util.temp_stream_read_buf += msgBuf;

                    if (stream_util.stream_msg_length == -1)
                    {
                        bufpair.outputs.push_back(stream_util.temp_stream_read_buf);
                        stream_util.temp_stream_read_buf.clear();
                    }
                }
                bytes_read = true;
            }

            if (res == -1)
            {
                return -1;
            }
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
     * Common function to create a socket (Hp->SC, SC->HP).
     * @param fds Vector to populate fd list.
     * @param socket_type Type of the socket. (SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET)
     * @return Returns -1 if socket creation fails otherwise 0.
     */
    int create_iosockets(std::vector<int> &fds, const int socket_type)
    {
        int socket[2] = {-1, -1};
        // Create the socket of given type.
        if (socketpair(AF_UNIX, socket_type, 0, socket) == -1)
        {
            LOG_ERROR << errno << ": Error when creating domain socket.";
            return -1;
        }

        // If socket got created, assign them to the fd vector.
        fds.clear();
        fds.push_back(socket[0]); //SCREADWRITE
        fds.push_back(socket[1]); //HPREADWRITE

        return 0;
    }

    /**
     * Common function to write the given input buffer into the write fd from the HP side socket.
     * @param fds Vector of fd list.
     * @param inputs Buffer to write into the HP write fd.
     * @param close_if_empty Close the socket after writing if this is true.
     */
    int write_iosocket_stream(std::vector<int> &fds, std::list<std::string> &inputs, const bool close_if_empty)
    {
        // Write the inputs (if any) into the contract.

        const int writefd = fds[SOCKETFDTYPE::HPREADWRITE];
        if (writefd == -1)
            return 0;

        bool write_error = false;

        if (!inputs.empty())
        {
            // Prepare the input memory segments to write with wrtiev.
            // Extra one element for the header.
            iovec memsegs[inputs.size() * 2 + 1];
            uint8_t header[inputs.size() * 4 + 4];
            header[0] = inputs.size() >> 24;
            header[1] = inputs.size() >> 16;
            header[2] = inputs.size() >> 8;
            header[3] = inputs.size();
            // Message count header.
            memsegs[0].iov_base = header;
            memsegs[0].iov_len = 4;
            size_t i = 1;
            for (std::string &input : inputs)
            {
                // 4 bytes for message len header.
                header[i * 4] = input.length() >> 24;
                header[i * 4 + 1] = input.length() >> 16;
                header[i * 4 + 2] = input.length() >> 8;
                header[i * 4 + 3] = input.length();
                memsegs[i * 2 - 1].iov_base = &header[i * 4];
                memsegs[i * 2 - 1].iov_len = 4;
                memsegs[i * 2].iov_base = input.data();
                memsegs[i * 2].iov_len = input.length();
                i++;
            }

            if (writev(writefd, memsegs, (inputs.size() * 2 + 1)) == -1)
                write_error = true;

            inputs.clear();
        }
        else if (close_if_empty)
        {
            close(writefd);
            fds[SOCKETFDTYPE::HPREADWRITE] = -1;
        }

        if (write_error)
            LOG_ERROR << errno << ": Error writing to stream socket.";

        return write_error ? -1 : 0;
    }

    /**
     * Common function to write the given input buffer into the write fd from the HP side socket.
     * @param fds Vector of fd list.
     * @param inputs Buffer to write into the HP write fd.
     * @param close_if_empty Close the socket after writing if this is true.
     */
    int write_iosocket_seq_packet(std::vector<int> &fds, std::list<std::string> &inputs, const bool close_if_empty)
    {
        // Write the inputs (if any) into the contract.
        const int writefd = fds[SOCKETFDTYPE::HPREADWRITE];
        if (writefd == -1)
            return 0;

        bool write_error = false;

        if (!inputs.empty())
        {
            for (std::string &input : inputs)
            {
                if (write(writefd, input.data(), input.length()) == -1)
                    write_error = true;
            }
        }
        else if (close_if_empty)
        {
            close(writefd);
            fds[SOCKETFDTYPE::HPREADWRITE] = -1;
        }
        if (write_error)
            LOG_ERROR << errno << ": Error writing to sequece packet socket.";

        return write_error ? -1 : 0;
    }

    /**
     * Common function to read buffered output from the sequence packet socket and populate the output.
     * @param fds Vector representing the socket fd list.
     * @param output The buffer to place the read output.
     * @return -1 on error. Otherwise no. of bytes read.
     */
    int read_iosocket_seq_packet(std::vector<int> &fds, std::string &output)
    {
        // Read any available data that have been written by the contract process
        // from the output socket and store in the output buffer.
        // Outputs will be read by the consensus process later when it wishes so.

        const int readfd = fds[SOCKETFDTYPE::HPREADWRITE];

        if (readfd == -1)
            return 0;

        // Available bytes returns the total number of bytes to read of multiple messages.
        size_t available_bytes = 0;
        if (ioctl(readfd, FIONREAD, &available_bytes) != -1)
        {
            if (available_bytes == 0)
                return 0;

            output.resize(MIN(MAX_SEQ_PACKET_SIZE, available_bytes));
            const int res = read(readfd, output.data(), MAX_SEQ_PACKET_SIZE);
            output.resize(res);

            if (res >= 0)
            {
                if (res == 0) // EOF
                {
                    close(readfd);
                    fds[SOCKETFDTYPE::HPREADWRITE] = -1;
                }
                return res;
            }
        }

        close(readfd);
        fds[SOCKETFDTYPE::HPREADWRITE] = -1;
        LOG_ERROR << errno << ": Error reading sequence packet socket.";

        return -1;
    }

    /**
     * Common function to read buffered output from the stream socket and populate the output list.
     * @param fds Vector representing the sockets fd list.
     * @param output The buffer to place the read output.
     * @return -1 on error. Otherwise no. of bytes read.
     */
    int read_iosocket_stream(std::vector<int> &fds, std::string &output)
    {
        // Read any available data that have been written by the contract process
        // from the output socket and store in the output buffer.
        // Outputs will be read by the consensus process later when it wishes so.

        const int readfd = fds[SOCKETFDTYPE::HPREADWRITE];
        if (readfd == -1)
            return 0;

        bool read_error = false;
        size_t available_bytes = 0;
        if (ioctl(readfd, FIONREAD, &available_bytes) != -1)
        {
            if (available_bytes == 0)
            {
                return 0;
            }

            output.resize(available_bytes);
            const int res = read(readfd, output.data(), available_bytes);

            if (res >= 0)
            {
                if (res == 0) // EOF
                {
                    close(readfd);
                    fds[SOCKETFDTYPE::HPREADWRITE] = -1;
                }
                return res;
            }
        }

        close(readfd);
        fds[SOCKETFDTYPE::HPREADWRITE] = -1;
        LOG_ERROR << errno << ": Error reading stream socket.";

        return -1;
    }

    void close_unused_fds(execution_context &ctx, const bool is_hp)
    {
        if (!ctx.args.readonly)
        {
            close_unused_socket_vectorfds(is_hp, ctx.hpscfds);
            close_unused_socket_vectorfds(is_hp, ctx.nplfds);
        }

        // Loop through user fds.
        for (auto &[pubkey, fds] : ctx.userfds)
            close_unused_socket_vectorfds(is_hp, fds);
    }

    /**
     * Common function for closing unused fds based on which process this gets called from.
     * This also marks active fds with O_CLOEXEC for close-on-exec behaviour.
     * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
     * @param fds Vector of fds to close.
     */
    void close_unused_socket_vectorfds(const bool is_hp, std::vector<int> &fds)
    {
        for (int fd_type = 0; fd_type <= 1; fd_type++)
        {
            const int fd = fds[fd_type];
            if (fd != -1)
            {
                if ((is_hp && fd_type == SOCKETFDTYPE::SCREADWRITE) ||
                    (!is_hp && fd_type == SOCKETFDTYPE::HPREADWRITE))
                {
                    close(fd);
                    fds[fd_type] = -1;
                }
                else if (is_hp && (fd_type == SOCKETFDTYPE::HPREADWRITE))
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
        args.hpscbufs.outputs.clear();
        // Empty npl message queue.
        while (args.npl_messages.pop())
        {
        }
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

        if (ctx.contract_io_thread.joinable())
            ctx.contract_io_thread.join();
    }

} // namespace sc
