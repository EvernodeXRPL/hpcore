#include "../pchheader.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "corebill.h"

namespace corebill
{

// How many violations can occur for a host before being escalated.
constexpr uint32_t VIOLATION_THRESHOLD = 10;

// Violation cooldown interval.
constexpr uint32_t VIOLATION_REFRESH_INTERVAL = 600 * 1000; // 10 minutes

// Keeps track of violation count against offending hosts.
std::unordered_map<std::string, violation_stat> violation_counter;

// Keeps the graylisted hosts.
util::ttl_set graylist;

// Keeps the whitelisted hosts who would be ignored in all violation tracking.
std::unordered_set<std::string> whitelist;

/**
 * Report a violation. Violation means a force disconnection of a socket due to some threshold exceeding.
 */
void report_violation(const std::string host)
{
    if (whitelist.find(host) != whitelist.end()) // Is in whitelist
    {
        LOG_DBG << host << " is whitelisted. Ignoring the violation.";
        return;
    }

    violation_stat &stat = violation_counter[host];

    const uint64_t time_now = util::get_epoch_milliseconds();

    stat.counter++;

    if (stat.timestamp == 0)
    {
        // Reset counter timestamp.
        stat.timestamp = time_now;
    }
    else
    {
        // Check whether we have exceeded the threshold within the monitering interval.
        const uint64_t elapsed_time = time_now - stat.timestamp;
        if (elapsed_time <= VIOLATION_REFRESH_INTERVAL && stat.counter > VIOLATION_THRESHOLD)
        {
            // IP exceeded violation threshold.

            stat.timestamp = 0;
            stat.counter = 0;

            graylist.emplace(host, VIOLATION_REFRESH_INTERVAL);
            LOG_WARN << host << " placed on graylist.";
        }
        else if (elapsed_time > VIOLATION_REFRESH_INTERVAL)
        {
            // Start the counter fresh.
            stat.timestamp = time_now;
            stat.counter = 1;
        }
    }
}

void add_to_whitelist(const std::string host)
{
    // Add to whitelist and remove from all other offender lists.
    whitelist.emplace(host);
    graylist.erase(host);
    violation_counter.erase(host);
}

void remove_from_whitelist(const std::string host)
{
    whitelist.erase(host);
}

bool is_banned(const std::string &host)
{
    return graylist.exists(host);
}

} // namespace corebill