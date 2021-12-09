#include "../pchheader.hpp"
#include "corebill.hpp"
#include "tracker.hpp"
#include "../util/util.hpp"

namespace corebill
{
    // How many violations can occur for a host before being escalated.
    constexpr uint32_t VIOLATION_THRESHOLD = 10;

    // Violation cooldown interval.
    constexpr uint32_t VIOLATION_REFRESH_INTERVAL = 600 * 1000; // 10 minutes

    constexpr uint32_t BAN_TTL_SEC = 600; // 10 mins.

    /**
     * Report a violation. Violation means a force disconnection of a socket due to some threshold exceeding.
     * When multiple violations occur within a time window, we ban that host from connecting again for a certain duration.
     */
    void tracker::report_violation(const std::string &host, const bool ipv4)
    {
        bool should_ban = false;

        {
            std::scoped_lock lock(this->violation_counter_mutex);

            violation_stat &stat = this->violation_counter[host];

            const uint64_t time_now = util::get_epoch_milliseconds();

            stat.counter++;

            if (stat.timestamp == 0)
            {
                stat.timestamp = time_now; // This host hasn't reported violations recently. So we set the timer from now on.
            }
            else
            {
                // Check whether we have exceeded the violation threshold within the time window.
                const uint64_t elapsed_time = time_now - stat.timestamp;
                if (elapsed_time <= VIOLATION_REFRESH_INTERVAL && stat.counter > VIOLATION_THRESHOLD)
                {
                    // IP exceeded violation threshold. We must ban the host.
                    should_ban = true;
                    this->violation_counter.erase(host);
                }
                else if (elapsed_time > VIOLATION_REFRESH_INTERVAL)
                {
                    // Start the counter fresh.
                    stat.timestamp = time_now;
                    stat.counter = 1;
                }
            }
        }

        if (should_ban)
        {
            LOG_WARNING << host << " is being banned.";
            ban_updates.enqueue(ban_update{true, ipv4, host, BAN_TTL_SEC});
        }
    }
}