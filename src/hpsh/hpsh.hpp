#ifndef _HP_HPSH_
#define _HP_HPSH_

#include <sys/socket.h>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <signal.h>
#include <unordered_map>
#include <list>
#include <thread>
#include <poll.h>
#include <wait.h>
#include <mutex>
#include "util.hpp"


namespace hpsh
{
    struct command_context
    {
        std::string pubkey;
        int child_fds[2];
        std::string response;
        bool read_completed = false;
    };

    struct hpsh_context
    {
        std::mutex command_mutex;
        std::list<command_context> commands;
        int control_fds[2];
        int hpsh_pid;
        std::thread watcher_thread;
        bool is_shutting_down;
    };

    extern hpsh_context ctx;

    int init();

    void deinit();

    int check_hpsh_exited(const bool block);

    int execute(std::string_view pubkey, std::string_view message);

    void response_watcher();
}

#endif