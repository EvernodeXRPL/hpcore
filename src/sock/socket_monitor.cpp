#include "socket_monitor.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../usr/user_session_handler.hpp"

namespace sock
{

/**
 * Act upon exceeding various thresholds in socket communication
 * 
 * @param threshold Type of threshold which has exceeded.
 * @param threshold_limit Threshold limit at the time of exceedance.
 * @param session Websocket session which exceeds the threshold.
 */
template <class T>
void threshold_monitor(util::SESSION_THRESHOLDS threshold, int64_t threshold_limit, socket_session<T> *session)
{
    if (threshold == util::SESSION_THRESHOLDS::MAX_BYTES_PER_MINUTE)
    {
        // Can act accordingly
        session->close();
    }
}

/**
 * Declaring templates with possible values for T because keeping all those in hpp file makes compile take a long time
 */
template void threshold_monitor(util::SESSION_THRESHOLDS threshold, int64_t threshold_limit, socket_session<p2p::peer_outbound_message> *session);

template void threshold_monitor(util::SESSION_THRESHOLDS threshold, int64_t threshold_limit, socket_session<usr::user_outbound_message> *session);
} // namespace sock