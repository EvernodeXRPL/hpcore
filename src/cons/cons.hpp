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
    int8_t stage;
    std::time_t novel_proposal_time;
    std::string lcl;
    std::string novel_proposal;
    std::map<std::string, std::pair<const std::string, std::string>> possible_inputs;
    std::map<std::string, std::pair<const std::string, std::string>> possible_outputs;

    std::unordered_map<std::string, std::pair<std::string, std::string>> local_userbuf;

    int32_t next_sleep;
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

extern consensus_context ctx;

void consensus();

void apply_ledger(const p2p::proposal &proposal);

float_t get_stage_threshold(int8_t stage);

void wait_for_proposals(bool reset);

void emit_stage0_proposal(time_t time_now);

p2p::proposal emit_stage123_proposal(
    time_t time_now, const std::list<p2p::proposal> &candidate_proposals, vote_counter &votes);

int8_t get_winning_stage(const std::list<p2p::proposal> &candidate_proposals, vote_counter &votes);

void run_contract_binary(std::time_t time);

} // namespace cons

#endif
