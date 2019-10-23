#ifndef _HP_CONS_H_
#define _HP_CONS_H_

#include <vector>
#include <unordered_map>
#include <ctime>
#include "../p2p/p2p.hpp"

namespace cons
{

//stage 1 vote threshold
static const float STAGE1_THRESHOLD = 0.5;
//stage 2 vote threshold
static const float STAGE2_THRESHOLD = 0.65;
//stage 3 vote threshold
static const float STAGE3_THRESHOLD = 0.8;


/**
 * This is used to store consensus information
 */
struct consensus_context
{
    std::vector<p2p::proposal> proposals;
    int stage;
    std::time_t novel_proposal_time;
    std::string lcl;
    std::string novel_proposal;
    std::unordered_map<std::string, std::string> possible_inputs;
    std::unordered_map<std::string, std::string> possible_outputs;
};

struct vote_counter
{
    std::unordered_map<int8_t, int32_t> stage;
    std::unordered_map<std::string, int32_t> lcl;
    std::unordered_map<std::string, int32_t> users;
    std::unordered_map<std::string, int32_t> inputs;
    std::unordered_map<std::string, int32_t> outputs;
    std::unordered_map<uint64_t, int32_t> time;
};

extern consensus_context consensus_ctx;

void consensus();

} // namespace cons

#endif
