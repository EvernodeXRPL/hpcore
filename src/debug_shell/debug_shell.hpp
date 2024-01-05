#ifndef _HP_DEBUG_SHELL_
#define _HP_DEBUG_SHELL_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../msg/usrmsg_common.hpp"

namespace debug_shell
{
    struct command_context
    {
        std::string id;
        std::string user_pubkey;
        int out_fd;
    };

    struct debug_shell_context
    {
        std::mutex command_mutex;
        std::list<command_context> commands;
        int control_fds[2];
        int debug_shell_pid;
        std::thread watcher_thread;
        bool is_shutting_down;
        bool is_initialized = false;
    };

    extern debug_shell_context ctx;

    int init();

    void deinit();

    int check_debug_shell_exited(const bool block);

    int send_terminate_message();

    void remove_user_commands(std::string_view user_pubkey);

    int execute(std::string_view id, std::string_view user_pubkey, std::string_view message);

    void response_watcher();
}

#endif