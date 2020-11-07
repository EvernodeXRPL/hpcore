#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session_threshold.hpp"
#include "../conf.hpp"
#include "../hpws/hpws.hpp"

namespace comm
{
    /** 
     * Represents an abstract channel to a Hot Pocket node.
     */
    class comm_session
    {
    public:
        std::string uniqueid;
        const bool is_self = false;

        comm_session(std::string_view id, const bool is_self);
        virtual int process_next_inbound_message() = 0;
        virtual int send(const std::vector<uint8_t> &message) = 0;
        virtual int send(std::string_view message) = 0;
        virtual void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms) = 0;
        virtual void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount) = 0;
        virtual const std::string display_name();
    };

} // namespace comm

#endif
