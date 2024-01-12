#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// BUILD_TIME symbol is populated via CMAKE build.
const char *build_time_sec_str = BUILD_TIME;
uint64_t MAX_LIMIT_SEC = 60 * 24 * 3600;
uint64_t build_time_sec = 0;

/**
 * Returns true if kill switch is activated (allowed time has expired).
 * Otherwise returns false (can keep using HotPocket).
 * @param epoch_ms Current time in epoch milliseconds.
 */
bool kill_switch(const uint64_t epoch_ms)
{
    // if (build_time_sec == 0)
    // {
    //     char *eptr;
    //     build_time_sec = strtoull(build_time_sec_str, &eptr, 10);
    // }

    // const uint64_t epoch_sec = epoch_ms / 1000;
    // return !(epoch_sec > build_time_sec && (epoch_sec - build_time_sec) <= MAX_LIMIT_SEC);
    
    // Commented out kill_switch code in case if it's needed in the future.
    return false;
}