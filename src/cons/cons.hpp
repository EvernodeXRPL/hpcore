#ifndef _HP_CONS_H_
#define _HP_CONS_H_

#include <vector>
#include <unordered_map>
#include <ctime>
#include "../p2p/p2p.hpp"

namespace cons
{

/**
 * This is used to store consensus information
 */
struct consensus_context
{
    std::vector<p2p::Proposal> proposals;
    int stage;
    std::time_t novel_proposal_time;
    std::string lcl;
    std::string novel_proposal;
};

extern consensus_context consensus_ctx;

void consensus();

} // namespace cons

#endif
