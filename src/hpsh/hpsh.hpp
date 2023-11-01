#ifndef _HP_HPSH_
#define _HP_HPSH_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../msg/usrmsg_common.hpp"

namespace hpsh
{
    struct command_context
    {
        std::string id;
        std::string user_pubkey;
        int child_fds[2];
    };

    struct hpsh_context
    {
        std::mutex command_mutex;
        std::list<command_context> commands;
        int control_fds[2];
        int hpsh_pid;
        std::thread watcher_thread;
        bool is_shutting_down;
        bool is_initialized = false;
    };

    extern hpsh_context ctx;

    int init();

    void deinit();

    int check_hpsh_exited(const bool block);

    int send_terminate_message();

    void remove_user_commands(std::string_view user_pubkey);

    int execute(std::string_view id, std::string_view user_pubkey, std::string_view message);

    void response_watcher();
}

#endif