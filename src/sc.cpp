#include "pchheader.hpp"
#include "conf.hpp"
#include "consensus.hpp"
#include "hplog.hpp"
#include "ledger.hpp"
#include "sc.hpp"
#include "hpfs/hpfs.hpp"
#include "msg/fbuf/p2pmsg_helpers.hpp"
#include "msg/controlmsg_common.hpp"
#include "msg/controlmsg_parser.hpp"
#include "unl.hpp"

namespace sc
{
    const uint32_t READ_BUFFER_SIZE = 128 * 1024; // This has to be minimum 128KB to support sequence packets.

    /**
     * Executes the contract process and passes the specified context arguments.
     * @return 0 on successful process creation. -1 on failure or contract process is already running.
     */
    int execute_contract(execution_context &ctx)
    {
        // Start the hpfs rw session before starting the contract process.
        if (start_hpfs_session(ctx) == -1)
            return -1;

        // Create the IO sockets for users, control channel and npl.
        // (Note: User socket will only be used for contract output only. For feeding user inputs we are using a memfd.)
        if (create_iosockets_for_fdmap(ctx.userfds, ctx.args.userbufs) == -1 ||
            create_iosockets(ctx.controlfds, SOCK_SEQPACKET) == -1 ||
            (!ctx.args.readonly && create_iosockets(ctx.nplfds, SOCK_SEQPACKET) == -1))
        {
            cleanup_fds(ctx);
            stop_hpfs_session(ctx);
            return -1;
        }

        LOG_DEBUG << "Starting contract process..." << (ctx.args.readonly ? " (rdonly)" : "");
        int ret = 0;

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

            // Clone the user inputs fd to be passed on to the contract.
            const int user_inputs_fd = dup(ctx.args.user_input_store.fd);
            lseek(user_inputs_fd, 0, SEEK_SET); // Reset seek position.

            // Write the contract execution args from HotPocket to the stdin (0) of the contract process.
            write_contract_args(ctx, user_inputs_fd);

            const bool using_appbill = !ctx.args.readonly && !conf::cfg.contract.appbill.mode.empty();
            int len = conf::cfg.contract.runtime_binexec_args.size() + 1;
            if (using_appbill)
                len += conf::cfg.contract.appbill.runtime_args.size();

            // Fill process args.
            char *execv_args[len];
            int j = 0;
            if (using_appbill)
            {
                for (int i = 0; i < conf::cfg.contract.appbill.runtime_args.size(); i++, j++)
                    execv_args[i] = conf::cfg.contract.appbill.runtime_args[i].data();
            }

            for (int i = 0; i < conf::cfg.contract.runtime_binexec_args.size(); i++, j++)
                execv_args[j] = conf::cfg.contract.runtime_binexec_args[i].data();
            execv_args[len - 1] = NULL;

            const std::string current_dir = conf::ctx.hpfs_mount_dir + "/" + ctx.args.hpfs_session_name + STATE_DIR_PATH;
            chdir(current_dir.c_str());

            execv(execv_args[0], execv_args);
            std::cerr << errno << ": Contract process execv failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting contract process." << (ctx.args.readonly ? " (rdonly)" : "");
            ret = -1;
        }

        cleanup_fds(ctx);

        util::h32 patch_hash;
        if (hpfs::get_hash(patch_hash, ctx.args.hpfs_dir, conf::PATCH_FILE_PATH) == 1)
        {
            if (patch_hash != hpfs::ctx.get_hash(hpfs::HPFS_PARENT_COMPONENTS::PATCH))
            {

                // Appling new patch file changes to hpcore runtime.
                if (conf::validate_and_apply_patch_config(conf::cfg.contract, ctx.args.hpfs_dir) == -1)
                {
                    LOG_ERROR << "Appling patch file after contract execution failed";
                }
                else
                {
                    // Update global hash tracker with the new patch file hash.
                    hpfs::ctx.set_hash(hpfs::HPFS_PARENT_COMPONENTS::PATCH, patch_hash);

                    unl::update_unl_changes_from_patch();
                }
            }
        }

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
     * Starts the hpfs virtual filesystem session used for contract execution.
     */
    int start_hpfs_session(execution_context &ctx)
    {
        if (!ctx.args.readonly)
            ctx.args.hpfs_session_name = hpfs::RW_SESSION_NAME;

        return ctx.args.readonly ? hpfs::start_ro_session(ctx.args.hpfs_session_name, false)
                                 : hpfs::acquire_rw_session();
    }

    /**
     * Stops the hpfs virtual filesystem session.
     */
    int stop_hpfs_session(execution_context &ctx)
    {
        if (ctx.args.readonly)
        {
            return hpfs::stop_ro_session(ctx.args.hpfs_session_name);
        }
        else
        {
            // Read the root hash if not in readonly mode.
            if (hpfs::get_hash(ctx.args.post_execution_state_hash, ctx.args.hpfs_session_name, STATE_DIR_PATH) < 1)
            {
                hpfs::release_rw_session();
                return -1;
            }
            return hpfs::release_rw_session();
        }
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
     *   "controlfd": fd,
     *   "nplfd":fd,
     *   "userinfd":fd, // User inputs fd.
     *   "users":{ "<pkhex>":[outfd, [msg1_off, msg1_len], ...], ... },
     *   "unl":[ "<pkhex>", ... ]
     * }
     */
    int write_contract_args(const execution_context &ctx, const int user_inputs_fd)
    {
        // Populate the json string with contract args.
        // We don't use a JSON parser here because it's lightweight to contrstuct the
        // json string manually.

        std::ostringstream os;
        os << "{\"version\":\"" << util::HP_VERSION
           << "\",\"pubkey\":\"" << conf::cfg.node.public_key_hex
           << "\",\"ts\":" << ctx.args.time
           << ",\"readonly\":" << (ctx.args.readonly ? "true" : "false");

        if (!ctx.args.readonly)
        {
            os << ",\"lcl\":\"" << ctx.args.lcl
               << "\",\"nplfd\":" << ctx.nplfds.scfd;
        }

        os << ",\"controlfd\":" << ctx.controlfds.scfd;

        os << ",\"userinfd\":" << user_inputs_fd
           << ",\"users\":{";

        user_json_to_stream(ctx.userfds, ctx.args.userbufs, os);

        os << "},\"unl\":" << unl::get_json() << "}";

        // Get the final json string that should be written to contract input pipe.
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

        // Prepare output poll fd list.
        // User out fds + control fd + NPL fd (NPL fd not available in readonly mode)
        const size_t out_fd_count = ctx.userfds.size() + (ctx.args.readonly ? 1 : 2);
        const size_t control_fd_idx = ctx.userfds.size();
        const size_t npl_fd_idx = control_fd_idx + 1;
        struct pollfd out_fds[out_fd_count];

        auto user_itr = ctx.userfds.begin();
        for (int i = 0; i < out_fd_count; i++)
        {
            const int fd = (user_itr != ctx.userfds.end()) ? (user_itr++)->second.hpfd
                                                           : (i == control_fd_idx ? ctx.controlfds.hpfd : ctx.nplfds.hpfd);
            out_fds[i] = {fd, POLLIN, 0};
        }

        while (!ctx.is_shutting_down)
        {
            // Reset the revents because we are reusing same pollfd list.
            for (int i = 0; i < out_fd_count; i++)
                out_fds[i].revents = 0;

            if (poll(out_fds, out_fd_count, 20) == -1)
            {
                LOG_ERROR << errno << ": Poll error in contract outputs.";
                break;
            }

            // Atempt to read messages from contract (regardless of contract terminated or not).
            const int control_read_res = read_control_outputs(ctx, out_fds[control_fd_idx]);
            const int npl_read_res = ctx.args.readonly ? 0 : read_npl_outputs(ctx, out_fds[npl_fd_idx]);
            const int user_read_res = read_contract_fdmap_outputs(ctx.userfds, out_fds, ctx.args.userbufs);

            if (ctx.termination_signaled || ctx.contract_pid == 0)
            {
                // If no bytes were read after contract finished execution, exit the loop.
                // Otherwise keep running the loop becaue there might be further messages to read.
                if ((control_read_res + npl_read_res + user_read_res) == 0)
                    break;
            }
            else
            {
                // We assume contract is still running. Attempt to write any queued messages to the contract.

                const int npl_write_res = ctx.args.readonly ? 0 : write_npl_messages(ctx);
                if (npl_write_res == -1)
                    break;

                const int control_write_res = write_control_inputs(ctx);
                if (control_write_res == -1)
                    break;
            }

            // Check if contract process has exited on its own during the loop.
            if (ctx.contract_pid > 0)
                check_contract_exited(ctx, false);
        }

        // Close all fds.
        cleanup_fds(ctx);

        // Purge any inputs we passed to the contract.
        for (const auto &[pubkey, bufs] : ctx.args.userbufs)
            for (const util::buffer_view &input : bufs.inputs)
                ctx.args.user_input_store.purge(input);

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
    int write_control_inputs(execution_context &ctx)
    {
        std::string control_msg;

        if (ctx.args.control_messages.try_dequeue(control_msg))
        {
            if (write_iosocket_seq_packet(ctx.controlfds, control_msg) == -1)
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
        const int writefd = ctx.nplfds.hpfd;

        if (writefd == -1)
            return 0;

        // Dequeue the next npl message from the queue.
        // Check the lcl against the latest lcl.
        p2p::npl_message npl_msg;
        if (ctx.args.npl_messages.try_dequeue(npl_msg))
        {
            if (npl_msg.lcl == ctx.args.lcl)
            {
                const std::string pubkeyhex = util::to_hex(npl_msg.pubkey);

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
    int read_control_outputs(execution_context &ctx, const pollfd pfd)
    {
        std::string output;
        const int res = read_iosocket(false, pfd, output);
        if (res == -1)
        {
            LOG_ERROR << "Error reading control message from the contract.";
        }
        else if (res > 0)
        {
            handle_control_msg(ctx, output);
        }

        return (res > 0) ? 1 : 0;
    }

    /**
     * Read all NPL output messages produced by the contract process and broadcast them.
     * @param ctx contract execution context.
     * @return 0 if no bytes were read. 1 if bytes were read.
     */
    int read_npl_outputs(execution_context &ctx, const pollfd pfd)
    {
        std::string output;
        const int res = read_iosocket(false, pfd, output);

        if (res == -1)
        {
            LOG_ERROR << "Error reading NPL output from the contract.";
        }
        else if (res > 0)
        {
            // Broadcast npl messages once contract npl output is collected.
            broadcast_npl_output(output);
        }

        return (res > 0) ? 1 : 0;
    }

    /**
     * Broadcast npl messages to peers. If the npl messages are set to private, broadcast only to the unl nodes. 
     * If it is public, broadcast to all the connected nodes. Npl messages are not sent in observer mode.
     * @param output Npl message to be broadcasted.
    */
    void broadcast_npl_output(std::string_view output)
    {
        // In observer mode, we do not send out npl messages.
        if (conf::cfg.node.role == conf::ROLE::OBSERVER || !conf::cfg.node.is_unl) // If we are a non-unl node, do not broadcast npl messages.
            return;

        if (!output.empty())
        {
            flatbuffers::FlatBufferBuilder fbuf(1024);
            msg::fbuf::p2pmsg::create_msg_from_npl_output(fbuf, output, ledger::ctx.get_lcl());
            p2p::broadcast_message(fbuf, true, false, !conf::cfg.contract.is_npl_public);
        }
    }

    void user_json_to_stream(const contract_fdmap_t &user_fdmap, const contract_bufmap_t &user_bufmap, std::ostringstream &os)
    {
        for (auto itr = user_fdmap.begin(); itr != user_fdmap.end(); itr++)
        {
            if (itr != user_fdmap.begin())
                os << ","; // Trailing comma separator for previous element.

            // Get the hex pubkey.
            const std::string &pubkey = itr->first; // Pubkey in binary format.
            const std::vector<util::buffer_view> &user_inputs = user_bufmap.find(pubkey)->second.inputs;

            // Write hex pubkey as key and output fd as first element of array.
            os << "\"" << util::to_hex(pubkey) << "\":["
               << itr->second.scfd;

            // Write input offsets into the same array.
            for (auto inp_itr = user_inputs.begin(); inp_itr != user_inputs.end(); inp_itr++)
                os << ",[" << inp_itr->offset << "," << inp_itr->size << "]";

            os << "]";
        }
    }

    /**
     * Creates io sockets for all pubkeys specified in bufmap.
     * @param fdmap A map which has public key and fd pair for that public key.
     * @param bufmap A map which has a public key and input/output buffer lists for that public key.
     * @return 0 on success. -1 on failure.
     */
    int create_iosockets_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap)
    {
        for (auto &[pubkey, buflist] : bufmap)
        {
            fd_pair fds = {};
            if (create_iosockets(fds, SOCK_STREAM) == -1)
                return -1;

            fdmap.emplace(pubkey, std::move(fds));
        }

        return 0;
    }

    /**
     * Common function to read all outputs produced by the contract process and store them in
     * output buffers for later processing.
     * 
     * @param fdmap A map which has public key and fd pair for that public key.
     * @param pfds Poll fd set for users (must be in same order as user fdmap).
     * @param bufmap A map which has a public key and input/output buffer pair for that public key.
     * @return 0 if no bytes were read. 1 if bytes were read.
     */
    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, const pollfd *pfds, contract_bufmap_t &bufmap)
    {
        bool bytes_read = false;
        int i = 0;
        for (auto &[pubkey, bufs] : bufmap)
        {
            // Get fds for the pubkey.
            std::string output;
            fd_pair &fds = fdmap[pubkey];

            // This returns the total bytes read from the socket.
            const int total_bytes_read = read_iosocket(true, pfds[i++], output);

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
     * @param fds fd pair to populate.
     * @param socket_type Type of the socket. (SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET)
     * @return Returns -1 if socket creation fails otherwise 0.
     */
    int create_iosockets(fd_pair &fds, const int socket_type)
    {
        int socket[2] = {-1, -1};
        // Create the socket of given type.
        if (socketpair(AF_UNIX, socket_type, 0, socket) == -1)
        {
            LOG_ERROR << errno << ": Error when creating domain socket.";
            return -1;
        }

        // If socket got created, assign them to the fd pair.
        fds.scfd = socket[0];
        fds.hpfd = socket[1];

        return 0;
    }

    /**
     * Common function to write the given input into the write fd from the HP side socket.
     * @param fds fd pair.
     * @param input Input to write into the HP write fd.
     */
    int write_iosocket_seq_packet(fd_pair &fds, std::string_view input)
    {
        // Write the inputs (if any) into the contract.
        const int writefd = fds.hpfd;
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
     * @param is_stream_socket Indicates whether socket is steam socket or not.
     * @param pfd The pollfd struct containing poll status.
     * @param output The buffer to place the read output.
     * @return -1 on error. Otherwise no. of bytes read.
     */
    int read_iosocket(const bool is_stream_socket, const pollfd pfd, std::string &output)
    {
        // Read any available data that have been written by the contract process
        // from the output socket and store in the output buffer.
        if (pfd.revents & POLLIN)
        {
            output.resize(READ_BUFFER_SIZE);
            const int res = read(pfd.fd, output.data(), READ_BUFFER_SIZE);
            if (res > 0)
                output.resize(res); // Resize back to the actual bytes read.

            if (res == -1)
                LOG_ERROR << errno << ": Error reading from contract socket. stream:" << is_stream_socket;

            return res;
        }
        return 0;
    }

    void close_unused_fds(execution_context &ctx, const bool is_hp)
    {
        if (!ctx.args.readonly)
        {
            close_unused_socket_fds(is_hp, ctx.nplfds);
        }

        close_unused_socket_fds(is_hp, ctx.controlfds);

        // Loop through user fds.
        for (auto &[pubkey, fds] : ctx.userfds)
            close_unused_socket_fds(is_hp, fds);
    }

    /**
     * Common function for closing unused fds based on which process this gets called from.
     * This also marks active fds with O_CLOEXEC for close-on-exec behaviour.
     * @param is_hp Specify 'true' when calling from HP process. 'false' from SC process.
     * @param fds fd pair to close.
     */
    void close_unused_socket_fds(const bool is_hp, fd_pair &fds)
    {
        if (is_hp)
        {
            if (fds.scfd != -1)
            {
                close(fds.scfd);
                fds.scfd = -1;
            }

            // The hp fd must be kept open in HP process. But we must
            // mark it to close on exec in a potential forked process.
            if (fds.hpfd != -1)
            {
                int flags = fcntl(fds.hpfd, F_GETFD, NULL);
                flags |= FD_CLOEXEC;
                fcntl(fds.hpfd, F_SETFD, flags);
            }
        }
        else
        {
            if (fds.hpfd != -1)
            {
                close(fds.hpfd);
                fds.hpfd = -1;
            }
        }
    }

    void cleanup_fds(execution_context &ctx)
    {
        cleanup_fd_pair(ctx.controlfds);
        cleanup_fd_pair(ctx.nplfds);
        for (auto &[pubkey, fds] : ctx.userfds)
            cleanup_fd_pair(fds);
        ctx.userfds.clear();
    }

    /**
     * Closes fds in a fd pair.
     */
    void cleanup_fd_pair(fd_pair &fds)
    {
        if (fds.hpfd != -1)
            close(fds.hpfd);
        if (fds.scfd != -1)
            close(fds.scfd);
        fds.hpfd = -1;
        fds.scfd = -1;
    }

    /**
     * Force cleanup any running processes for the specified execution context.
     */
    void stop(execution_context &ctx)
    {
        ctx.is_shutting_down = true;
    }

    void handle_control_msg(execution_context &ctx, std::string_view msg)
    {
        msg::controlmsg::controlmsg_parser parser;
        std::string type;
        if (parser.parse(msg) == -1 || parser.extract_type(type) == -1)
            return;

        if (type == msg::controlmsg::MSGTYPE_CONTRACT_END)
        {
            ctx.termination_signaled = true;
        }
    }

} // namespace sc
