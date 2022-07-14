#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../consensus.hpp"
#include "../hplog.hpp"
#include "../ledger/ledger.hpp"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../msg/controlmsg_common.hpp"
#include "../msg/controlmsg_parser.hpp"
#include "../unl.hpp"
#include "../util/version.hpp"
#include "../p2p/p2p.hpp"
#include "contract_serve.hpp"
#include "sc.hpp"
#include "hpfs_log_sync.hpp"

namespace sc
{
    constexpr uint32_t READ_BUFFER_SIZE = 128 * 1024; // This has to be minimum 128KB to support sequence packets.
    constexpr int FILE_PERMS = 0644;
    constexpr int CONTRACT_LOG_PERMS = 0664;
    constexpr const char *STDOUT_LOG = ".stdout.log";
    constexpr const char *STDERR_LOG = ".stderr.log";
    constexpr const char *POST_EXEC_SCRIPT = "post_exec.sh";

    constexpr uint32_t CONTRACT_FS_ID = 0;

    sc::contract_mount contract_fs;         // Global contract file system instance.
    sc::contract_sync contract_sync_worker; // Global contract file system sync instance.
    sc::contract_serve contract_server;     // Contract file server instance.

    int max_sc_log_size_bytes; // Store the max contract log file limit in bytes.

    int init()
    {
        if (contract_fs.init(CONTRACT_FS_ID, conf::ctx.contract_hpfs_dir, conf::ctx.contract_hpfs_mount_dir, conf::ctx.contract_hpfs_rw_dir,
                             conf::cfg.contract.run_as.to_string(), conf::cfg.node.history == conf::HISTORY::FULL) == -1)
        {
            LOG_ERROR << "Contract file system initialization failed.";
            return -1;
        }

        if (contract_server.init("cont", &contract_fs) == -1)
        {
            LOG_ERROR << "Contract file system serve worker initialization failed.";
            return -1;
        }

        if (conf::cfg.node.history == conf::HISTORY::FULL)
        {
            hpfs_log_sync::init();
        }
        else
        {
            if (contract_sync_worker.init("cont", &contract_fs) == -1)
            {
                LOG_ERROR << "Contract file system sync worker initialization failed.";
                return -1;
            }
        }
        if (conf::cfg.contract.log.enable)
        {
            max_sc_log_size_bytes = conf::cfg.contract.log.max_mbytes_per_file * 1024 * 1024;
            clean_extra_contract_log_files(hpfs::RW_SESSION_NAME, STDOUT_LOG, conf::cfg.contract.log.max_file_count);
            clean_extra_contract_log_files(hpfs::RW_SESSION_NAME, STDERR_LOG, conf::cfg.contract.log.max_file_count);
        }
        return 0;
    }

    void deinit()
    {
        if (conf::cfg.node.history == conf::HISTORY::FULL)
            hpfs_log_sync::deinit();
        else
            contract_sync_worker.deinit();

        contract_server.deinit();
        contract_fs.deinit();
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

        // Set contract working directory.
        ctx.working_dir = contract_fs.physical_path(ctx.args.hpfs_session_name, STATE_DIR_PATH);

        // Setup contract output log file paths (for consensus execution only).
        if (conf::cfg.contract.log.enable && !ctx.args.readonly)
        {
            // We keep appending logs to the same out/err files (Rollout log files are maintained according to the hp config settings).
            const std::string prefix = ctx.args.hpfs_session_name;
            ctx.stdout_file = conf::ctx.contract_log_dir + "/" + prefix + STDOUT_LOG;

            struct stat st_stdout;
            if (stat(ctx.stdout_file.data(), &st_stdout) != -1 &&
                st_stdout.st_size >= max_sc_log_size_bytes &&
                rename_and_cleanup_contract_log_files(prefix, STDOUT_LOG) == -1)
            {
                LOG_ERROR << "Failed cleaning up and renaming contract stdout log files.";
                return -1;
            }

            ctx.stderr_file = conf::ctx.contract_log_dir + "/" + prefix + STDERR_LOG;

            struct stat st_stderr;
            if (stat(ctx.stderr_file.data(), &st_stderr) != -1 &&
                st_stderr.st_size >= max_sc_log_size_bytes &&
                rename_and_cleanup_contract_log_files(prefix, STDERR_LOG) == -1)
            {
                LOG_ERROR << "Failed cleaning up and renaming contract stderr log files.";
                return -1;
            }
        }

        // Create the IO sockets for users, control channel and npl.
        // (Note: User socket will only be used for contract output only. For feeding user inputs we are using a memfd.)
        if (create_iosockets_for_fdmap(ctx.user_fds, ctx.args.userbufs) == -1 ||
            create_iosockets(ctx.control_fds, SOCK_SEQPACKET) == -1 ||
            (!ctx.args.readonly && create_iosockets(ctx.npl_fds, SOCK_SEQPACKET) == -1))
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

            if (insert_demarkation_line(ctx) == -1)
            {
                std::cerr << errno << ": Contract process inserting demarkation line failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }

            // Set process resource limits.
            if (set_process_rlimits() == -1)
            {
                std::cerr << errno << ": Failed to set contract process resource limits." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }

            // Close all fds unused by SC process.
            close_unused_fds(ctx, false);

            // Clone the user inputs fd to be passed on to the contract.
            const int user_inputs_fd = dup(ctx.args.user_input_store.fd);
            lseek(user_inputs_fd, 0, SEEK_SET); // Reset seek position.

            // Write the contract execution args from HotPocket to the stdin (0) of the contract process.
            write_contract_args(ctx, user_inputs_fd);

            // Fill process args.
            int execv_len = conf::cfg.contract.runtime_binexec_args.size() + 1;
            char *execv_args[execv_len];
            int j = 0;

            for (size_t i = 0; i < conf::cfg.contract.runtime_binexec_args.size(); i++, j++)
                execv_args[j] = conf::cfg.contract.runtime_binexec_args[i].data();
            execv_args[execv_len - 1] = NULL;

            const int env_len = conf::cfg.contract.runtime_env_args.size() + 1;
            char *env_args[env_len];
            for (size_t i = 0; i < conf::cfg.contract.runtime_env_args.size(); i++)
                env_args[i] = conf::cfg.contract.runtime_env_args[i].data();
            env_args[env_len - 1] = NULL;

            if (chdir(ctx.working_dir.c_str()) == -1)
            {
                std::cerr << errno << ": Contract process chdir failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }

            // Just before we execv the contract binary, we set user execution user/group if specified in hp config.
            // (Must set gid before setting uid)
            if (!conf::cfg.contract.run_as.empty() && (setgid(conf::cfg.contract.run_as.gid) == -1 || setuid(conf::cfg.contract.run_as.uid) == -1))
            {
                std::cerr << errno << ": Contract process setgid/uid failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }

            // We do not create logs files in readonly execution due to the difficulty in managing the log file limits.
            (conf::cfg.contract.log.enable && !ctx.args.readonly)
                ? execv_and_redirect_logs(execv_len - 1, (const char **)execv_args, ctx.stdout_file, ctx.stderr_file, (const char **)env_args)
                : execve(execv_args[0], execv_args, env_args);
            std::cerr << errno << ": Contract process execve() failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting contract process." << (ctx.args.readonly ? " (rdonly)" : "");
            ret = -1;
        }

        cleanup_fds(ctx);

        // If the consensus contact finished executing successfully, run the post-exec.sh script if it exists.
        if (ctx.exit_success && !ctx.args.readonly && run_post_exec_script(ctx) == -1)
            ret = -1;

        if (stop_hpfs_session(ctx) == -1)
            ret = -1;

        return ret;
    }

    int set_process_rlimits()
    {
        rlimit lim;
        if (conf::cfg.contract.round_limits.proc_cpu_seconds > 0)
        {
            lim.rlim_cur = lim.rlim_max = conf::cfg.contract.round_limits.proc_cpu_seconds;
            if (setrlimit(RLIMIT_CPU, &lim) == -1)
                return -1;
        }

        if (conf::cfg.contract.round_limits.proc_mem_bytes > 0)
        {
            lim.rlim_cur = lim.rlim_max = conf::cfg.contract.round_limits.proc_mem_bytes;
            if (setrlimit(RLIMIT_DATA, &lim) == -1)
                return -1;
        }

        if (conf::cfg.contract.round_limits.proc_ofd_count > 0)
        {
            lim.rlim_cur = lim.rlim_max = conf::cfg.contract.round_limits.proc_ofd_count;
            if (setrlimit(RLIMIT_NOFILE, &lim) == -1)
                return -1;
        }

        return 0;
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
                ctx.exit_success = true;
                LOG_DEBUG << "Contract process" << (ctx.args.readonly ? " (rdonly)" : "") << " ended normally.";
                return 1;
            }
            else
            {
                LOG_WARNING << "Contract process" << (ctx.args.readonly ? " (rdonly)" : "") << " ended prematurely. Exit code " << WEXITSTATUS(scstatus);
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

        return ctx.args.readonly ? contract_fs.start_ro_session(ctx.args.hpfs_session_name, false)
                                 : contract_fs.acquire_rw_session();
    }

    /**
     * Stops the hpfs virtual filesystem session.
     */
    int stop_hpfs_session(execution_context &ctx)
    {
        if (ctx.args.readonly)
        {
            return contract_fs.stop_ro_session(ctx.args.hpfs_session_name);
        }
        else
        {
            // Read the state hash if not in readonly mode.
            if (contract_fs.get_hash(ctx.args.post_execution_state_hash, ctx.args.hpfs_session_name, STATE_DIR_PATH) < 1)
            {
                contract_fs.release_rw_session();
                return -1;
            }

            util::h32 patch_hash;
            const int patch_hash_result = contract_fs.get_hash(patch_hash, ctx.args.hpfs_session_name, PATCH_FILE_PATH);

            if (patch_hash_result == -1)
            {
                contract_fs.release_rw_session();
                return -1;
            }
            else if (patch_hash_result == 1 && patch_hash != contract_fs.get_parent_hash(PATCH_FILE_PATH))
            {
                // Update global hash tracker of contract fs with the new patch file hash.
                contract_fs.set_parent_hash(PATCH_FILE_PATH, patch_hash);
                // Denote that the patch file was updated by the SC.
                consensus::is_patch_update_pending = true;
            }

            return contract_fs.release_rw_session();
        }
    }

    /**
     * Writes the contract args (JSON) into the stdin of the contract process.
     * Args format:
     * {
     *   "hp_version":"<hp version>",
     *   "contract_id": "<contract guid>",
     *   "public_key": "<this node's hex public key>",
     *   "private_key": "<this node's hex private key>",
     *   "timestamp": <this node's timestamp (unix milliseconds)>,
     *   "readonly": <true|false>,
     *   "lcl_seq_no": "<lcl sequence no>",
     *   "lcl_hex": "<lcl hash hex>",
     *   "control_fd": fd,
     *   "npl_fd":fd,
     *   "user_in_fd":fd, // User inputs fd.
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
        os << "{\"hp_version\":\"" << version::HP_VERSION
           << "\",\"contract_id\":\"" << conf::cfg.contract.id
           << "\",\"public_key\":\"" << conf::cfg.node.public_key_hex
           << "\",\"private_key\":\"" << conf::cfg.node.private_key_hex
           << "\",\"timestamp\":" << ctx.args.time
           << ",\"readonly\":" << (ctx.args.readonly ? "true" : "false");

        if (!ctx.args.readonly)
        {
            os << ",\"lcl_seq_no\":" << ctx.args.lcl_id.seq_no
               << ",\"lcl_hash\":\"" << util::to_hex(ctx.args.lcl_id.hash.to_string_view())
               << "\",\"npl_fd\":" << ctx.npl_fds.scfd;
        }

        os << ",\"control_fd\":" << ctx.control_fds.scfd;

        os << ",\"user_in_fd\":" << user_inputs_fd
           << ",\"users\":{";

        user_json_to_stream(ctx.user_fds, ctx.args.userbufs, os);

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
        const size_t out_fd_count = ctx.user_fds.size() + (ctx.args.readonly ? 1 : 2);
        const size_t control_fd_idx = ctx.user_fds.size();
        const size_t npl_fd_idx = control_fd_idx + 1;
        struct pollfd out_fds[out_fd_count];

        auto user_itr = ctx.user_fds.begin();
        for (size_t i = 0; i < out_fd_count; i++)
        {
            const int fd = (user_itr != ctx.user_fds.end()) ? (user_itr++)->second.hpfd
                                                            : (i == control_fd_idx ? ctx.control_fds.hpfd : ctx.npl_fds.hpfd);
            out_fds[i] = {fd, POLLIN, 0};
        }

        while (!ctx.is_shutting_down)
        {
            // Reset the revents because we are reusing same pollfd list.
            for (size_t i = 0; i < out_fd_count; i++)
                out_fds[i].revents = 0;

            if (poll(out_fds, out_fd_count, 20) == -1)
            {
                LOG_ERROR << errno << ": Poll error in contract outputs.";
                break;
            }

            // Atempt to read messages from contract (regardless of contract terminated or not).
            const int control_read_res = read_control_outputs(ctx, out_fds[control_fd_idx]);
            const int npl_read_res = ctx.args.readonly ? 0 : read_npl_outputs(ctx, &out_fds[npl_fd_idx]);
            const int user_read_res = read_contract_fdmap_outputs(ctx.user_fds, out_fds, ctx.args.userbufs);

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
     * Runs the contract post execution script if exists.
     */
    int run_post_exec_script(execution_context &ctx)
    {
        // Check whether the post-exec script exists within contract state dir.
        const std::string script_path = ctx.working_dir + "/" + POST_EXEC_SCRIPT;
        if (!util::is_file_exists(script_path.c_str()))
            return 0;

        LOG_INFO << "Running post-exec script...";
        const pid_t pid = fork();
        if (pid == 0)
        {
            // Child process.
            util::fork_detach();

            const std::string script_args = std::to_string(ctx.args.lcl_id.seq_no) + " " + util::to_hex(ctx.args.lcl_id.hash.to_string_view());

            // We set current working dir and pass command line arg to the script.
            char *argv[] = {(char *)POST_EXEC_SCRIPT, (char *)script_args.data(), (char *)NULL};
            if (chdir(ctx.working_dir.c_str()) == -1)
            {
                std::cerr << errno << ": Post-exec script chdir failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }
            // Set user execution user/group if specified (Must set gid before setting uid).
            if (!conf::cfg.contract.run_as.empty() && (setgid(conf::cfg.contract.run_as.gid) == -1 || setuid(conf::cfg.contract.run_as.uid) == -1))
            {
                std::cerr << errno << ": Post-exec script setgid/uid failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
                exit(1);
            }

            conf::cfg.contract.log.enable ? execv_and_redirect_logs(2, (const char **)argv, ctx.stdout_file, ctx.stderr_file)
                                          : execv(argv[0], argv);
            std::cerr << errno << ": Post-exec script execv() failed." << (ctx.args.readonly ? " (rdonly)" : "") << "\n";
            exit(1);
        }
        else if (pid > 0)
        {
            // Hot Pocket process.
            int status = 0;
            if (waitpid(pid, &status, 0) == -1)
            {
                LOG_ERROR << errno << ": waitpid after post-exec script execv failed.";
                return -1;
            }
            // If the script returns a code 0 or 3 to 125 we consider it a successful execition.
            // If the script returns code 0, we consider script lifetime is over and delete the file. Otherwise we retain the file.
            const int exit_code = WEXITSTATUS(status);
            if (WIFEXITED(status) && (exit_code == 0 || (exit_code > 2 && exit_code < 126)))
            {
                LOG_INFO << "Post-exec script executed successfully. Exit code:" << exit_code;
                // Exit code 0 means post-execution script can be deleted.
                if (exit_code == 0 && util::remove_file(script_path) == -1)
                {
                    LOG_ERROR << errno << ": Error deleting post-exec script after execution.";
                    return -1;
                }
            }
            else
            {
                LOG_ERROR << "Post-exec script ended prematurely. Exit code:" << exit_code;
                return -1;
            }
        }
        else
        {
            // Fork failed.
            LOG_ERROR << "Fork failed while running post-exec script.";
            return -1;
        }
        return 0;
    }

    /**
     * Writes any hp input messages to the contract.
     */
    int write_control_inputs(execution_context &ctx)
    {
        std::string control_msg;

        if (ctx.args.control_messages.try_dequeue(control_msg))
        {
            if (write_iosocket_seq_packet(ctx.control_fds, control_msg) == -1)
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
        const int writefd = ctx.npl_fds.hpfd;

        if (writefd == -1)
            return 0;

        // Dequeue the next npl message from the queue.
        // Check the last pramary shard against the latest last pramary shard.
        p2p::npl_message npl_msg;
        if (ctx.args.npl_messages.try_dequeue(npl_msg))
        {
            if (npl_msg.lcl_id == ctx.args.lcl_id)
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
                LOG_DEBUG << "NPL message dropped due to last primary shard mismatch.";
            }
        }

        return 0;
    }

    /**
     * Read all HP output messages produced by the contract process and store them in
     * the buffer for later processing.
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
    int read_npl_outputs(execution_context &ctx, pollfd *pfd)
    {
        std::string output;
        const int res = read_iosocket(false, *pfd, output);

        if (res == -1)
        {
            LOG_ERROR << "Error reading NPL output from the contract.";
        }
        else if (res > 0)
        {
            ctx.total_npl_output_size += output.size();
            if (conf::cfg.contract.round_limits.npl_output_bytes > 0 &&
                ctx.total_npl_output_size > conf::cfg.contract.round_limits.npl_output_bytes)
            {
                close(pfd->fd);
                pfd->fd = -1;
            }
            else
            {
                // Broadcast npl messages once contract npl output is collected.
                broadcast_npl_output(output);
            }
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
            flatbuffers::FlatBufferBuilder fbuf;
            msg::fbuf::p2pmsg::create_msg_from_npl_output(fbuf, output, ledger::ctx.get_lcl_id());
            p2p::broadcast_message(fbuf, true, false, !conf::cfg.contract.is_npl_public, 1); // Use high priority send.
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
     * @param fdmap A map which has public key and fd pair for that public key.
     * @param pfds Poll fd set for users (must be in same order as user fdmap).
     * @param bufmap A map which has a public key and input/output buffer pair for that public key.
     * @return 0 if no bytes were read. 1 if bytes were read.
     */
    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, pollfd *pfds, contract_bufmap_t &bufmap)
    {
        bool bytes_read = false;
        int i = 0;
        for (auto &[pubkey, bufs] : bufmap)
        {
            // Get fds for the pubkey.
            std::string output;

            // This returns the total bytes read from the socket.
            const int total_bytes_read = (pfds[i].fd == -1) ? 0 : read_iosocket(true, pfds[i], output);

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
                    std::string msg_buf = output.substr(pos, possible_read_len);
                    pos += possible_read_len;
                    // Append the extracted message chunk to the current message.
                    current_output.message += msg_buf;
                }

                // Increment total collected output len for this user.
                bufs.total_output_len += total_bytes_read;

                // If total outputs exceeds limit for this user, close the user's out fd.
                if (conf::cfg.contract.round_limits.user_output_bytes > 0 &&
                    bufs.total_output_len > conf::cfg.contract.round_limits.user_output_bytes)
                {
                    close(pfds[i].fd);
                    pfds[i].fd = -1;
                }
                else
                {
                    bytes_read = true;
                }
            }

            i++;
        }

        return bytes_read ? 1 : 0;
    }

    /**
     * Insert a demarkation line in to the contract log files.
     * @param ctx The contract execution context.
     */
    int insert_demarkation_line(execution_context &ctx)
    {
        if (!conf::cfg.contract.log.enable || ctx.args.readonly)
            return 0;

        // The permissions of a created file are restricted by the process's current umask, so group and world write are always disabled by default.
        // We do the fchmod seperatly after opening the file. Because if we give the g+w permission in open() mode param,
        // The file won't get that permission because of the above mentioned default umask.

        // Set write permission for the contract logs.
        // Because if run as user is set, contract logs are modified by the contract user.
        const int outfd = open(ctx.stdout_file.data(), O_CREAT | O_WRONLY | O_APPEND, FILE_PERMS);
        if (outfd == -1 || fchmod(outfd, CONTRACT_LOG_PERMS) == -1)
        {
            std::cerr << errno << ": Error opening " << ctx.stdout_file << "\n";
            return -1;
        }

        const int errfd = open(ctx.stderr_file.data(), O_CREAT | O_WRONLY | O_APPEND, FILE_PERMS);
        if (errfd == -1 || fchmod(errfd, CONTRACT_LOG_PERMS) == -1)
        {
            close(outfd);
            std::cerr << errno << ": Error opening " << ctx.stderr_file << "\n";
            return -1;
        }

        const std::string header = "Execution lcl " + ctx.args.lcl_id.to_string() + "\n";
        if (write(outfd, header.data(), header.size()) == -1 ||
            write(errfd, header.data(), header.size()) == -1)
        {
            close(outfd);
            close(errfd);
            std::cerr << errno << ": Error writing contract execution log header.\n";
            return -1;
        }

        close(outfd);
        close(errfd);
        return 0;
    }

    /**
     * Redirect stdout/err to given log files.
     * @param execv_argc Command argument count.
     * @param execv_argv Command arguments.
     * @param stdout_file File to redirect stdout.
     * @param stderr_file File to redirect stderr.
     * @param env_argc Optional environment argument count.
     * @param env_argv Optional environment arguments.
     */
    int execv_and_redirect_logs(const int execv_argc, const char *execv_argv[], std::string_view stdout_file, std::string_view stderr_file, const char *env_argv[])
    {
        std::string cmd = "(";

        for (int i = 0; i < execv_argc; i++)
        {
            if (i == 0)
            {
                const std::string realpath = util::realpath(execv_argv[i]);
                if (!realpath.empty())
                    cmd.append(realpath).append(" ");
                else
                {
                    // If real path fails, we get the current dir as exec bin path.
                    std::array<char, PATH_MAX> buffer;
                    if (!getcwd(buffer.data(), buffer.size()))
                    {
                        std::cerr << errno << ": Error in executable path." << std::endl;
                        return -1;
                    }
                    cmd.append(buffer.data()).append("/").append(execv_argv[i]).append(" ");
                }
            }
            else
                cmd.append(execv_argv[i]).append(" ");
        }

        cmd.append("| tee -a ").append(stdout_file).append(") 3>&1 1>&2 2>&3 | tee -a ").append(stderr_file);
        // Command tee can only accept stdout, so swap stdout and stderr by 3>&1 1>&2 2>&3.
        // 3>&1 will create new file descriptor 3 and redirect it to 1(stdout).
        // Then 1>&2 will redirect file descriptor 1(stdout) to 2(stderr).
        // Then 2>&3 will redirect file descriptor 2(stderr) to 3(stdout).

        return env_argv != NULL ? execle("/bin/sh", "sh", "-c", cmd.data(), (char *)NULL, env_argv) : execl("/bin/sh", "sh", "-c", cmd.data(), (char *)NULL);
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
            {
                LOG_ERROR << errno << ": Error reading from contract socket. stream:" << is_stream_socket;
            }

            return res;
        }
        return 0;
    }

    void close_unused_fds(execution_context &ctx, const bool is_hp)
    {
        if (!ctx.args.readonly)
        {
            close_unused_socket_fds(is_hp, ctx.npl_fds);
        }

        close_unused_socket_fds(is_hp, ctx.control_fds);

        // Loop through user fds.
        for (auto &[pubkey, fds] : ctx.user_fds)
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
        cleanup_fd_pair(ctx.control_fds);
        cleanup_fd_pair(ctx.npl_fds);
        for (auto &[pubkey, fds] : ctx.user_fds)
            cleanup_fd_pair(fds);
        ctx.user_fds.clear();
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
        else if (type == msg::controlmsg::MSGTYPE_PEER_CHANGESET)
        {
            std::vector<p2p::peer_properties> added_peers;
            std::vector<p2p::peer_properties> removed_peers;
            if (parser.extract_peer_changeset(added_peers, removed_peers) != -1)
                p2p::merge_peer_list("Control_MSG", &added_peers, &removed_peers);
        }
    }

    /**
     * Rename the files to make the new file the root log file. (eg: rw.stdout.log). The oldest file is deleted to make the room for the new file.
     * Other files are renamed to the next level (eg: rw_1.stdout.log to rw_2.stdout.log).
     * @param session_name hpfs session name for filename.
     * @param postfix Postfix for the file name (Either stdout.log or stderr.log).
     * @param depth Depth of the recursion. Starts with zero and traverse down.
     * @return 0 on success and -1 on error.
     */
    int rename_and_cleanup_contract_log_files(const std::string &session_name, std::string_view postfix, const size_t depth)
    {
        const std::string prefix = (depth == 0) ? session_name : (session_name + "_" + std::to_string(depth));
        const std::string filename = conf::ctx.contract_log_dir + "/" + prefix + postfix.data();

        if (!util::is_file_exists(filename) || depth > conf::cfg.contract.log.max_file_count - 1)
            return 0;

        // Abort if an error occured in previous round.
        if (rename_and_cleanup_contract_log_files(session_name, postfix, depth + 1) == -1)
            return -1;

        if (depth == (conf::cfg.contract.log.max_file_count - 1))
        {
            // Last allowed file. remove this to make room for the new one.
            const int res = util::remove_file(filename);
            if (res == -1)
            {
                LOG_ERROR << errno << ": Error removing " << filename << " to make room for new log file.";
            }

            return res;
        }

        // Rename file one step up. Eg: rw_1.stdout.log to rw_2.stdout.log.
        const std::string new_filename = conf::ctx.contract_log_dir + "/" + session_name + "_" + std::to_string(depth + 1) + postfix.data();
        const int res = rename(filename.data(), new_filename.data());
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error occured while renaming " << filename << " to " << new_filename;
        }

        return res;
    }

    /**
     * Cleanup extra contract log files when max file limit changes on startup.
     * @param session_name hpfs session name.
     * @param postfix Postfix for the file name (Either stdout.log or stderr.log).
     * @param start_point Start point to start removing files.
     */
    void clean_extra_contract_log_files(const std::string &session_name, std::string_view postfix, const int start_point)
    {
        int current = start_point;
        const std::string fliename_common_part = conf::ctx.contract_log_dir + "/" + session_name + "_";
        std::string filename = fliename_common_part + std::to_string(current) + postfix.data();
        while (util::is_file_exists(filename))
        {
            if (util::remove_file(filename) == -1)
            {
                LOG_ERROR << "Error removing " << filename << " during contract log file cleanup.";
            }

            filename = fliename_common_part + std::to_string(++current) + postfix.data();
        }

        const int removed_count = current - start_point;
        if (removed_count > 0)
        {
            LOG_DEBUG << (current - start_point) << " " << postfix << " contract log files cleaned up with log file count change.";
        }
    }

} // namespace sc
