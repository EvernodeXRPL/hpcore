#include "pchheader.hpp"
#include "health.hpp"
#include "p2p/p2p.hpp"
#include "util/util.hpp"
#include "status.hpp"
#include "hplog.hpp"

namespace health
{
    proposal_health phealth = {};

    void report_proposal_batch(const std::list<p2p::proposal> &proposals)
    {
        phealth.comm_latency_min = 0;
        phealth.comm_latency_max = 0;
        phealth.comm_latency_avg = 0;
        phealth.read_latency_min = 0;
        phealth.read_latency_max = 0;
        phealth.read_latency_avg = 0;
        phealth.batch_size = proposals.size();

        if (phealth.batch_size == 0)
            return;

        const uint64_t now = util::get_epoch_milliseconds();
        uint64_t total_comm_latency = 0;
        uint64_t total_read_latency = 0;

        for (const p2p::proposal &p : proposals)
        {
            const uint64_t comm_latency = (p.sent_timestamp < p.recv_timestamp) ? (p.recv_timestamp - p.sent_timestamp) : 0;
            const uint64_t read_latency = now - p.recv_timestamp;

            total_comm_latency += comm_latency;
            total_read_latency += read_latency;

            if (comm_latency < phealth.comm_latency_min)
                phealth.comm_latency_min = comm_latency;

            if (comm_latency < phealth.comm_latency_max)
                phealth.comm_latency_max = comm_latency;

            if (read_latency < phealth.read_latency_min)
                phealth.read_latency_min = read_latency;

            if (read_latency < phealth.read_latency_max)
                phealth.read_latency_max = read_latency;
        }

        phealth.comm_latency_avg = total_comm_latency / phealth.batch_size;
        phealth.read_latency_avg = total_read_latency / phealth.batch_size;
    }

    void emit_health_stats()
    {
    }
}