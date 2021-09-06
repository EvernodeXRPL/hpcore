#ifndef _HP_HEALTH_
#define _HP_HEALTH_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

namespace health
{
    struct proposal_health
    {
        uint64_t comm_latency_min = 0;
        uint64_t comm_latency_max = 0;
        uint64_t comm_latency_avg = 0;
        uint64_t read_latency_min = 0;
        uint64_t read_latency_max = 0;
        uint64_t read_latency_avg = 0;
        uint64_t batch_size = 0;
    };

    void report_proposal_batch(const std::list<p2p::proposal> &proposals);
    void emit_health_stats();

} // namespace health

#endif
