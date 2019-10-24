#ifndef _HP_CONS_H_
#define _HP_CONS_H_

#include <vector>
#include <unordered_map>
#include <list>
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
    std::list<p2p::proposal> proposals;
    int8_t stage;
    std::time_t novel_proposal_time;
    std::string lcl;
    std::string novel_proposal;
    std::map<std::string, std::pair<const std::string, std::string>> possible_inputs;
    std::map<std::string, std::pair<const std::string, std::string>> possible_outputs;
    int32_t next_sleep;
};

std::map<std::string, std::pair<const std::string, const std::string>> local_inputs;
std::unordered_map<std::string, std::pair<std::string, std::string>> local_userbuf;//local_outputs

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

void apply_ledger(p2p::proposal proposal);

void run_contract_binary();
} // namespace cons

#endif
