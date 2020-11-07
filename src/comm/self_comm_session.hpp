#ifndef _HP_SELF_COMM_SESSION_
#define _HP_SELF_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session.hpp"
#include "comm_session_threshold.hpp"
#include "../p2p/peer_session_handler.hpp"


namespace comm
{
    /** 
     * Represents an active WebSocket connection
     */
    class self_comm_session : public comm_session
    {
    private:
        moodycamel::ConcurrentQueue<std::string> msg_queue; // Holds self messages waiting to be processed.
        p2p::peer_session_handler peer_sess_handler;

    public:
        self_comm_session();
        int process_next_inbound_message();
        int send(const std::vector<uint8_t> &message);
        int send(std::string_view message);
        void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
        void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
    };

} // namespace comm

#endif
