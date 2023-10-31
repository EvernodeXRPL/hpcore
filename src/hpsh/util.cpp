#include "util.hpp"

namespace util
{
    constexpr mode_t DIR_PERMS = 0755;

    /**
     * Sleeps the current thread for specified no. of milliseconds.
     */
    void sleep(const uint64_t milliseconds)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    // Applies signal mask to the calling thread.
    void mask_signal()
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
    }

    /**
     * Clears signal mask and signal handlers from the caller.
     * Called by other processes forked from hpcore threads so they get detatched from
     * the hpcore signal setup.
     */
    void fork_detach()
    {
        // Restore signal handlers to defaults.
        signal(SIGINT, SIG_DFL);
        signal(SIGSEGV, SIG_DFL);
        signal(SIGABRT, SIG_DFL);

        // Remove any signal masks applied by hpcore.
        sigset_t mask;
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);

        // Set process group id (so the terminal doesn't send kill signals to forked children).
        setpgrp();
    }
} // namespace util
