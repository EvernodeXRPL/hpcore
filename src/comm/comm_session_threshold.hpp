#ifndef _HP_COMM_COMM_SESSION_THRESHOLD_
#define _HP_COMM_COMM_SESSION_THRESHOLD_

#include "../pchheader.hpp"

namespace comm
{

/**
 * Enum used to track down various thresholds used in socket communication.
 */
enum SESSION_THRESHOLDS
{
    // Max incoming bytes per minute.
    MAX_RAWBYTES_PER_MINUTE = 0,

    // Max duplicate messages per minute.
    MAX_DUPMSGS_PER_MINUTE = 1,

    // Max messages with invalid signature per minute.
    MAX_BADSIGMSGS_PER_MINUTE = 2,

    // Max messages with bad structure per minute.
    MAX_BADMSGS_PER_MINUTE = 3,

    // Idle connection timeout.
    IDLE_CONNECTION_TIMEOUT = 4
};

/*
* Use this to keep in track of different thresholds which we need to deal with. e.g - maximum amount of bytes allowed per minute through a session
* threshold_limit - Maximum threshold value which is allowed
* counter_value - Counter which keeps incrementing per every message
* timestamp - Timestamp when counter value changes
* intervalms - Time interval in miliseconds in which the threshold and the counter value should be compared
*/
struct session_threshold
{
    uint64_t threshold_limit = 0;
    uint32_t intervalms = 0;
    uint64_t counter_value = 0;
    uint64_t timestamp = 0;

    session_threshold(const uint64_t threshold_limit, const uint32_t intervalms)
        : threshold_limit(threshold_limit), intervalms(intervalms)
    {
    }
};

} // namespace comm

#endif