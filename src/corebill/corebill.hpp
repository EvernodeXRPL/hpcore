#ifndef _HP_COREBILL_
#define _HP_COREBILL_

#include "../pchheader.hpp"

namespace corebill
{

    /**
 * Keeps the violation counter and the timestamp of the monitoring window.
 */
    struct violation_stat
    {
        uint32_t counter = 0;
        uint64_t timestamp = 0;
    };

    struct ban_update
    {
        bool is_ban = false;  // Whether to ban or unban.
        bool is_ipv4 = false; // If host is ipv4 or ipv6.
        std::string host;
        uint32_t ttl_sec; // Time in seconds to enforce the ban. Relevent only for bans.
    };

} // namespace corebill

#endif