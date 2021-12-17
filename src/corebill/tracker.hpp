#ifndef _HP_COREBILL_TRACKER_
#define _HP_COREBILL_TRACKER_

#include "../pchheader.hpp"
#include "../util/ttl_set.hpp"
#include "corebill.hpp"

namespace corebill
{
    class tracker
    {
    private:
        // Keeps track of violation count against offending hosts.
        std::unordered_map<std::string, violation_stat> violation_counter;
        util::ttl_set banned_hosts;
        std::mutex ban_mutex;

    public:
        moodycamel::ConcurrentQueue<ban_update> ban_updates;
        void report_violation(const std::string &host, const bool ipv4, const std::string &reason);
        bool is_banned(const std::string &host);
    };
}

#endif