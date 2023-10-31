#ifndef _HP_UTIL_UTIL_
#define _HP_UTIL_UTIL_

#include <sys/socket.h>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <sstream>
#include <signal.h>
#include <unordered_map>
#include <vector>
#include <thread>
#include <poll.h>

/**
 * Contains helper functions and data structures used by multiple other subsystems.
 */

namespace util
{
    void sleep(const uint64_t milliseconds);

    void mask_signal();

    void fork_detach();

} // namespace util

#endif
