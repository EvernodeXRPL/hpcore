#ifndef _HP_CONS_H_
#define _HP_CONS_H_

#include <vector>
#include <unordered_map>
#include <list>
#include <ctime>
#include "../proc.hpp"
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
    std::list<p2p::proposal> candidate_proposals;
    std::unordered_map<std::string, std::list<util::hash_buffer>> candidate_users;

    uint8_t stage;
    uint64_t novel_proposal_time;
    uint64_t time_now;
    std::string lcl;
    uint64_t led_seq_no;
    std::string novel_proposal;

    std::map<std::string, std::pair<const std::string, std::string>> possible_inputs;
    std::map<std::string, std::pair<const std::string, std::string>> possible_outputs;

    std::unordered_map<std::string, proc::contract_iobuf_pair> useriobufmap;

    int32_t next_sleep;
};

struct vote_counter
{
    std::map<uint8_t, int32_t> stage;
    std::map<uint64_t, int32_t> time;
    std::map<std::string, int32_t> lcl;
    std::map<std::string, int32_t> users;
    std::map<std::string, int32_t> inputs;
    std::map<std::string, int32_t> outputs;
};

extern consensus_context ctx;

int init();

void consensus();

void apply_ledger(const p2p::proposal &proposal);

float_t get_stage_threshold(uint8_t stage);

void timewait_stage(bool reset);

void populate_candidate_users_and_inputs();

p2p::proposal create_stage0_proposal();

p2p::proposal create_stage123_proposal(vote_counter &votes);

int broadcast_proposal(const p2p::proposal &p);

void check_majority_stage(bool &is_desync, bool &should_reset, uint8_t &majority_stage, vote_counter &votes);

void check_lcl_votes(bool &is_desync, bool &should_request_history, std::string &majority_lcl, vote_counter &votes);

void run_contract_binary(std::int64_t time);

} // namespace cons

#endif
