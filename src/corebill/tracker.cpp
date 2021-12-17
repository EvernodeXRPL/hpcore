#include "../pchheader.hpp"
#include "corebill.hpp"
#include "tracker.hpp"
#include "../util/util.hpp"

namespace corebill
{
    // How many violations can a host make within the refresh interval before being banned.
    constexpr uint32_t VIOLATION_THRESHOLD = 5;

    // Violation cooldown interval.
    constexpr uint32_t VIOLATION_REFRESH_INTERVAL = 600 * 1000; // 10 minutes

    // Ban period.
    constexpr uint32_t BAN_TTL_SEC = 600; // 10 minutes.

    /**
     * Report a violation. Violation means the connection has displayed a bad behaviour.
     * When multiple violations occur within a time window, we ban that host from connecting again for a certain duration.
     */
    void tracker::report_violation(const std::string &host, const bool ipv4, const std::string &reason)
    {
        std::scoped_lock lock(ban_mutex);

        violation_stat &stat = violation_counter[host];
        const uint64_t time_now = util::get_epoch_milliseconds();

        LOG_INFO << "Reported violation '" << reason << "' from " << host;

        // Check whether we have exceeded the violation threshold within the time window.
        const uint64_t elapsed_time = time_now - stat.timestamp;
        if (elapsed_time <= VIOLATION_REFRESH_INTERVAL && (stat.counter + 1) > VIOLATION_THRESHOLD)
        {
            violation_counter.erase(host);

            // IP exceeded violation threshold. We must ban the host.
            LOG_WARNING << "Banning " << host << " for " << BAN_TTL_SEC << "s";
            ban_updates.enqueue(ban_update{true, ipv4, host, BAN_TTL_SEC}); // Inform hpws about the ban.
            banned_hosts.emplace(host, BAN_TTL_SEC * 1000);                 // Add to local ban list to cross-check outgoing connections.
            return;
        }

        if (stat.timestamp == 0 || elapsed_time > VIOLATION_REFRESH_INTERVAL)
        {
            // Start the counter fresh.
            stat.timestamp = time_now;
            stat.counter = 1;
        }
        else
        {
            stat.counter++;
        }
    }

    bool tracker::is_banned(const std::string &host)
    {
        std::scoped_lock lock(ban_mutex);
        return banned_hosts.exists(host);
    }
}