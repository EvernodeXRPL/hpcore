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
    const uint32_t MAX_SEQ_PACKET_SIZE = 128 * 1024;
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

        // Setup user io sockets and feed all inputs to them.
        create_iosockets_for_fdmap(ctx.userfds, ctx.args.userbufs);

        if (!ctx.args.readonly)
        {
            // Create sequential packet sockets for npl messages.
            create_iosockets(ctx.nplfds, SOCK_SEQPACKET);
        }

        // Create sequential packet sockets for hp messages.
        create_iosockets(ctx.hpscfds, SOCK_SEQPACKET);

        int ret = 0;

        LOG_DEBUG << "Starting contract process..." << (ctx.args.readonly ? " (rdonly)" : "");

        const pid_t pid = fork();
        if (pid > 0)
        {
            // HotPocket process.
            ctx.contract_pid = pid;

            // Close all fds unused by HP process.
            close_unused_fds(ctx, true);

            // Start the contract monitor thread.
            ctx.contract_monitor_thread = std::thread(contract_monitor_loop, std::ref(ctx));

            // Wait for the contract monitor thread to gracefully stop along with the contract process.
            if (ctx.contract_monitor_thread.joinable())
                ctx.contract_monitor_thread.join();
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

            execv(execv_args[0], execv_args);
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

        return ret;
    }

    /**
     * Checks whether the contract process has exited.
     * @param ctx Contract execution context.
     * @param block Whether to block and wait until the contract has exited.
     * @return 0 if child has not exited. 1 if exited successfully. -1 if exited abnormally
     */
    int check_contract_exited(execution_context &ctx, const bool block)
    {
        int scstatus = 0;
        const int wait_res = waitpid(ctx.contract_pid, &scstatus, block ? 0 : WNOHANG);

        if (wait_res == 0) // Child still running.
        {
            return 0;
        }
        if (wait_res == -1)
        {
            LOG_ERROR << errno << ": Contract process waitpid error. pid:" << ctx.contract_pid;
            ctx.contract_pid = 0;
            return -1;
        }
        else // Child has exited
        {
            ctx.contract_pid = 0;

            if (WIFEXITED(scstatus))
            {
                LOG_DEBUG << "Contract process" << (ctx.args.readonly ? " (rdonly)" : "") << " ended normally.";
                return 1;
            }
            else
            {
                LOG_ERROR << "Contract process" << (ctx.args.readonly ? " (rdonly)" : "") << " ended with code " << WEXITSTATUS(scstatus);
                return -1;
            }
        }
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
     *   "hpfd": fd,
     *   "nplfd":fd,
     *   "usrfd":{ "<pkhex>":fd, ... },
     *   "unl":[ "<pkhex>", ... ]
     * }
     */
    int write_contract_args(const execution_context &ctx)
    {
        // Populate the json string with contract args.
        // We don't use a JSON parser here because it's lightweight to contrstuct the
        // json string manually.

        std::ostringstream os;
        os << "{\"version\":\"" << util::HP_VERSION
           << "\",\"pubkey\":\"" << conf::cfg.pubkeyhex.substr(2)
           << "\",\"ts\":" << ctx.args.time
           << ",\"readonly\":" << (ctx.args.readonly ? "true" : "false");

        if (!ctx.args.readonly)
        {
            os << ",\"lcl\":\"" << ctx.args.lcl
               << "\",\"nplfd\":" << ctx.nplfds[SOCKETFDTYPE::SCREADWRITE];
        }

        os << ",\"hpfd\":" << ctx.hpscfds[SOCKETFDTYPE::SCREADWRITE];
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

    /**
     * Feeds and collect contract messages.
     * @param ctx Contract execution context.
    */
    void contract_monitor_loop(execution_context &ctx)
    {
        util::mask_signal();

        // Write any user inputs to the contract.
        if (write_contract_fdmap_inputs(ctx.userfds, ctx.args.userbufs) == -1)
        {
            LOG_ERROR << "Failed to write user inputs to contract.";
        }
        else
        {
            while (!ctx.is_shutting_down)
            {
                // Atempt to read messages from contract (regardless of contract terminated or not).
                const int hpsc_read_res = read_contract_hp_outputs(ctx);
                const int npl_read_res = ctx.args.readonly ? 0 : read_contract_npl_outputs(ctx);
                const int user_read_res = read_contract_fdmap_outputs(ctx.userfds, ctx.args.userbufs);

                if (ctx.termination_signaled || ctx.contract_pid == 0)
                {
                    // If no bytes were read after contract finished execution, exit the loop.
                    // Otherwise keep running the loop becaue there might be further messages to read.
                    if ((hpsc_read_res + npl_read_res + user_read_res) == 0)
                        break;
                }
                else
                {
                    // We assume contract is still running. Attempt to write any queued messages to the contract.

                    const int npl_write_res = ctx.args.readonly ? 0 : write_npl_messages(ctx);
                    if (npl_write_res == -1)
                        break;

                    const int hpsc_write_res = write_contract_hp_inputs(ctx);
                    if (hpsc_write_res == -1)
                        break;

                    // If no operation was performed during this iteration, wait for a small delay until the next iteration.
                    // This means there were no queued messages from either side.
                    if ((hpsc_read_res + npl_read_res + user_read_res + hpsc_write_res + hpsc_write_res) == 0)
                        util::sleep(20);
                }

                // Check if contract process has exited on its own during the loop.
                if (ctx.contract_pid > 0)
                    check_contract_exited(ctx, false);
            }
        }

        // Close all fds.
        cleanup_vectorfds(ctx.hpscfds);
        cleanup_vectorfds(ctx.nplfds);
        for (auto &[pubkey, fds] : ctx.userfds)
            cleanup_vectorfds(fds);
        ctx.userfds.clear();

        // If we reach this point but the contract is still running, then we need to kill the contract by force.
        // This can be the case if HP is shutting down, or there was an error in initial feeding of inputs.
        if (ctx.contract_pid > 0)
        {
            // Check if the contract has exited voluntarily.
            if (check_contract_exited(ctx, false) == 0)
            {
                // Issue kill signal if the contract hasn't indicated the termination control message.
                if (!ctx.termination_signaled)
                    kill(ctx.contract_pid, SIGTERM);
                check_contract_exited(ctx, true); // Blocking wait until exit.
            }
        }

        LOG_DEBUG << "Contract monitor stopped";
    }

    /**
     * Writes any hp input messages to the contract.
     */
    int write_contract_hp_inputs(execution_context &ctx)
    {
        std::string control_msg;

        if (ctx.args.control_messages.try_dequeue(control_msg))
        {
            if (write_iosocket_seq_packet(ctx.hpscfds, control_msg) == -1)
            {
                LOG_ERROR << "Error writing HP inputs to SC";
                return -1;
            }
        }

        return 0;
    }

    /**
     * Write npl messages to the contract.
     * @param ctx Contract execution context.
     * @return Returns -1 when fails. 0 if no messages were written. 1 if some messages were written.
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
            if (npl_msg.lcl == ctx.args.lcl)
            {
                std::string pubkeyhex;
                util::bin2hex(
                    pubkeyhex,
                    reinterpret_cast<const unsigned char *>(npl_msg.pubkey.data()) + 1, // Skip first byte for key type prefix.
                    npl_msg.pubkey.length() - 1);

                // Writing the public key to the contract's fd (Skip first byte for key type prefix).
                if (write(writefd, pubkeyhex.data(), pubkeyhex.size()) == -1)
                {
                    LOG_ERROR << errno << ": Error writing npl message pubkey.";
                    return -1;
                }

                // Writing the message to the contract's fd.
                if (write(writefd, npl_msg.data.data(), npl_msg.data.size()) == -1)
                {
                    LOG_ERROR << errno << ": Error writing npl message data.";
                    return -1;
                }

                return 1;
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
     * @return 0 if no bytes were read. 1 if bytes were read..
     */
    int read_contract_hp_outputs(execution_context &ctx)
    {
        std::string output;
        const int hpsc_res = read_iosocket(false, ctx.hpscfds, output);
        if (hpsc_res == -1)
        {
            LOG_ERROR << "Error reading HP output from the contract.";
        }
        else if (hpsc_res > 0)
        {
            handle_control_msgs(ctx, output);
        }

        return (hpsc_res > 0) ? 1 : 0;
    }

    /**
     * Read all NPL output messages produced by the contract process and broadcast them.
     * @param ctx contract execution context.
     * @return 0 if no bytes were read. 1 if bytes were read.
     */
    int read_contract_npl_outputs(execution_context &ctx)
    {
        std::string output;
        const int npl_res = read_iosocket(false, ctx.nplfds, output);

        if (npl_res == -1)
        {
            LOG_ERROR << "Error reading NPL output from the contract.";
        }
        else if (npl_res > 0)
        {
            // Broadcast npl messages once contract npl output is collected.
            broadcast_npl_output(output);
        }

        return (npl_res > 0) ? 1 : 0;
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

    int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
    {
        // Loop through input buffers for each pubkey.
        for (auto &[pubkey, buflist] : bufmap)
        {
            if (write_iosocket_stream(fdmap[pubkey], buflist.inputs) == -1)
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
     * @return 0 if no bytes were read. 1 if bytes were read.
     */
    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
    {
        bool bytes_read = false;
        for (auto &[pubkey, bufs] : bufmap)
        {
            // Get fds for the pubkey.
            std::string output;
            std::vector<int> &fds = fdmap[pubkey];

            // This returns the total bytes read from the socket.
            const int total_bytes_read = read_iosocket(true, fds, output);

            if (total_bytes_read == -1)
            {
                LOG_ERROR << "Error reading user outputs from contract.";
            }
            else if (total_bytes_read > 0)
            {
                // Current reading position of the received buffer chunk.
                int pos = 0;
                // Go through the buffer to the end.
                while (pos < total_bytes_read)
                {
                    // Check whether the output list is empty or the last message stored is finished reading.
                    // If so, an empty container is added to store the new message.
                    if (bufs.outputs.empty() || (bufs.outputs.back().message.length() == bufs.outputs.back().message_len))
                    {
                        // Add new empty container.
                        bufs.outputs.push_back(contract_output());
                    }

                    // Get the laterst element from the list.
                    contract_output &current_output = bufs.outputs.back();

                    // This is a new container. Message len of container is defaults to 0.
                    if (current_output.message_len == 0)
                    {
                        // Extract the message length from four byte header in the buffer.
                        // Length received is in Big Endian format.
                        // Re-construct it into natural order. (No matter the format computer saves it in).
                        current_output.message_len = (uint8_t)output[pos] << 24 | (uint8_t)output[pos + 1] << 16 | (uint8_t)output[pos + 2] << 8 | (uint8_t)output[pos + 3];
                        // Advance the current position.
                        pos += 4;
                    }
                    // Store the possible message length which could be read from the remaining buffer length.
                    int possible_read_len;

                    // Checking whether the remaing buffer length is long enough to finish reading the current message.
                    if (((total_bytes_read - pos) - (current_output.message_len - current_output.message.length())) >= 0)
                    {
                        // Can finish reading a full message. Possible length is equal to the remaining message length.
                        possible_read_len = current_output.message_len - current_output.message.length();
                    }
                    else
                    {
                        // Only partial message is recieved. Store the received bytes until other chunk is received.
                        possible_read_len = total_bytes_read - pos;
                    }
                    // Extract the message chunk from the buffer.
                    std::string msgBuf = output.substr(pos, possible_read_len);
                    pos += possible_read_len;
                    // Append the extracted message chunk to the current message.
                    current_output.message += msgBuf;
                }

                bytes_read = true;
            }
        }

        return bytes_read ? 1 : 0;
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
     */
    int write_iosocket_stream(std::vector<int> &fds, std::list<std::string> &inputs)
    {
        // Write the inputs (if any) into the contract.

        const int writefd = fds[SOCKETFDTYPE::HPREADWRITE];
        if (writefd == -1)
            return 0;

        bool write_error = false;

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
            const uint32_t len = input.length();
            header[i * 4] = len >> 24;
            header[i * 4 + 1] = len >> 16;
            header[i * 4 + 2] = len >> 8;
            header[i * 4 + 3] = len;
            memsegs[i * 2 - 1].iov_base = &header[i * 4];
            memsegs[i * 2 - 1].iov_len = 4;
            memsegs[i * 2].iov_base = input.data();
            memsegs[i * 2].iov_len = input.length();
            i++;
        }

        if (writev(writefd, memsegs, (inputs.size() * 2 + 1)) == -1)
            write_error = true;

        inputs.clear();

        if (write_error)
            LOG_ERROR << errno << ": Error writing to stream socket.";

        return write_error ? -1 : 0;
    }

    /**
     * Common function to write the given input into the write fd from the HP side socket.
     * @param fds Vector of fd list.
     * @param input Input to write into the HP write fd.
     */
    int write_iosocket_seq_packet(std::vector<int> &fds, std::string_view input)
    {
        // Write the inputs (if any) into the contract.
        const int writefd = fds[SOCKETFDTYPE::HPREADWRITE];
        if (writefd == -1)
            return 0;

        if (write(writefd, input.data(), input.length()) == -1)
        {
            LOG_ERROR << errno << ": Error writing to sequece packet socket.";
            return -1;
        }

        return 0;
    }

    /**
     * Common function to read buffered output from the socket and populate the output.
     * @param is_stream_socket Indicates whether socket is steam socket or not
     * @param fds Vector representing the socket fd list.
     * @param output The buffer to place the read output.
     * @return -1 on error. Otherwise no. of bytes read.
     */
    int read_iosocket(const bool is_stream_socket, std::vector<int> &fds, std::string &output)
    {
        // Read any available data that have been written by the contract process
        // from the output socket and store in the output buffer.
        // Outputs will be read by the consensus process later when it wishes so.

        const int readfd = fds[SOCKETFDTYPE::HPREADWRITE];
        int res = 0;

        if (readfd == -1)
            return 0;

        // Available bytes returns the total number of bytes to read of multiple messages.
        size_t available_bytes = 0;
        if (ioctl(readfd, FIONREAD, &available_bytes) != -1)
        {
            if (available_bytes == 0)
            {
                res = 0;
            }
            else
            {
                const size_t bytes_to_read = is_stream_socket ? available_bytes : MIN(MAX_SEQ_PACKET_SIZE, available_bytes);
                output.resize(bytes_to_read);
                const int read_res = read(readfd, output.data(), bytes_to_read);

                if (read_res >= 0)
                {
                    res = read_res;
                    if (is_stream_socket)
                        output.resize(read_res);
                }
                else
                {
                    res = -1;
                    LOG_ERROR << errno << ": Error reading from contract socket.";
                }
            }
        }
        else
        {
            res = -1;
        }

        return res;
    }

    void close_unused_fds(execution_context &ctx, const bool is_hp)
    {
        if (!ctx.args.readonly)
        {
            close_unused_socket_vectorfds(is_hp, ctx.nplfds);
        }

        close_unused_socket_vectorfds(is_hp, ctx.hpscfds);

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

    /**
     * Force cleanup any running processes for the specified execution context.
     */
    void stop(execution_context &ctx)
    {
        ctx.is_shutting_down = true;
    }

    void handle_control_msgs(execution_context &ctx, std::string &msg)
    {
        if (msg == "Terminated")
        {
            ctx.termination_signaled = true;
        }
        msg.clear();
    }

} // namespace sc
