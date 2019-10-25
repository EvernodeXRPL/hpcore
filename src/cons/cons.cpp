
#include <ctime>
#include <unordered_map>
#include <list>
#include <math.h>
#include <chrono>
#include <thread>
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../p2p/p2p.hpp"
#include "../p2p/peer_message_handler.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../hplog.hpp"
#include "../crypto.hpp"
#include "../proc.hpp"
#include <flatbuffers/flatbuffers.h>
#include "cons.hpp"

namespace cons
{

consensus_context ctx;

/**
 * Increment voting table counter.
 * 
 * @param counter The counter map in which a vote should be incremented.
 * @param candidate The candidate whose vote should be increased by 1.
 */
template <typename T>
void increment(std::unordered_map<T, int32_t> &counter, const T &candidate)
{
    if (counter.count(candidate))
        counter[candidate]++;
    else
        counter.try_emplace(candidate, 1);
}

void consensus()
{
    // A consensus round consists of 4 stages (0,1,2,3).

    time_t time_now = std::time(nullptr);

    if (ctx.stage == 0)
    {
        // In stage 0 we create a novel stg_prop and broadcast it.
        emit_stage0_proposal(time_now);
    }
    else // Stage 1, 2, 3
    {
        // Move over the incoming proposals collected via the network so far into a private list
        // for this stage's processing.
        std::list<p2p::proposal> candidate_proposals;
        candidate_proposals.swap(p2p::collected_msgs.proposals);

        // Initialize vote counters
        vote_counter votes;

        int8_t winning_stage = get_winning_stage(candidate_proposals, votes);

        // check if we're ahead/behind of consensus
        if (winning_stage < ctx.stage - 1)
        {
            LOG_DBG << "Wait for proposals becuase node stage: " << std::to_string(ctx.stage)
                    << " is ahead of consensus stage: " << std::to_string(winning_stage);

            bool reset = (time_now - ctx.novel_proposal_time) < floor(conf::cfg.roundtime / 4);
            return wait_for_proposals(reset);
        }
        else if (winning_stage > ctx.stage - 1)
        {
            LOG_DBG << "Wait for proposals becuase node stage: " << std::to_string(ctx.stage)
                    << " is behind of consensus " << std::to_string(winning_stage);

            return wait_for_proposals(true);
        }

        // In stage 1, 2, 3 we vote for incoming proposals and promote winning votes based on thresholds.
        p2p::proposal stg_prop = emit_stage123_proposal(time_now, candidate_proposals, votes);

        candidate_proposals.clear();

        if (ctx.stage == 3)
        {
            LOG_DBG << "Stage 3 consensus reached. Applying ledger...";
            apply_ledger(stg_prop);
        }
    }

    // We have finished a consensus round (all 4 stages).

    // Transition to next stage.
    ctx.stage = (ctx.stage + 1) % 4;

    auto time_to_sleep = conf::cfg.roundtime / 4;

    // after a stage 0 novel proposal we will just busy wait for proposals
    if (ctx.stage == 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    else
        std::this_thread::sleep_for(std::chrono::milliseconds(time_to_sleep));
}

void emit_stage0_proposal(time_t time_now)
{
    // The proposal we are going to emit in stage 0.
    p2p::proposal stg_prop;
    stg_prop.time = time_now;
    stg_prop.stage = ctx.stage;
    stg_prop.lcl = ctx.lcl;
    ctx.novel_proposal_time = time_now;

    // Remove any useless proposals collected via the network so we'll have a cleaner stg_prop set to look
    // at when we transition to stage 1.
    {
        std::lock_guard<std::mutex> lock(p2p::collected_msgs.proposals_mutex);

        auto itr = p2p::collected_msgs.proposals.begin();
        while (itr != p2p::collected_msgs.proposals.end())
        {
            // Remove any stg_prop from previous round's stage 3.
            // Remove any stg_prop from self (pubkey match).
            // todo: check the state of these to ensure we're running consensus ledger
            if (itr->stage == 3 || conf::cfg.pubkey == itr->pubkey)
                p2p::collected_msgs.proposals.erase(itr++);
            else
                ++itr;
        }
    }

    // Populate the stg_prop with users list (user pubkey list) and their inputs.
    {
        std::lock_guard<std::mutex> lock(usr::users_mutex);
        for (auto &[sid, user] : usr::users)
        {
            // add all the user connections we host
            stg_prop.users.emplace(user.pubkey);

            // and all their pending messages
            if (!user.inbuffer.empty())
            {
                std::string input;
                input.swap(user.inbuffer);
                stg_prop.raw_inputs.try_emplace(user.pubkey, std::move(input));
            }
        }
    }

    // Populate the stg_prop with any contract outputs from previous round's stage 3.
    for (auto &[pubkey, bufpair] : ctx.local_userbuf)
    {
        if (!bufpair.second.empty()) // bufpair.second is the output buffer.
        {
            std::string rawoutput;
            rawoutput.swap(bufpair.second);

            stg_prop.raw_outputs.try_emplace(pubkey, std::move(rawoutput));
        }
    }
    ctx.local_userbuf.clear();

    // todo: set propsal states
    // todo: generate stg_prop hash and check with ctx.novel_proposal, we are sending same stg_prop again/

    // Broadcast stg_prop to peers
    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    p2p::create_msg_from_proposal(msg.builder(), stg_prop);
    {
        std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
        for (auto &[k, session] : p2p::peer_connections)
            session->send(msg);
    }
}

p2p::proposal emit_stage123_proposal(
    time_t time_now, const std::list<p2p::proposal> &candidate_proposals, vote_counter &votes)
{
    // The proposal to be emited at the end of this stage.
    p2p::proposal stg_prop;
    stg_prop.time = std::time(nullptr); // Current time.
    stg_prop.stage = ctx.stage;
    stg_prop.lcl = ctx.lcl;

    //todo:check lcl votes and wait for proposals

    // Vote for rest of the proposal fields
    for (const p2p::proposal &cp : candidate_proposals)
    {
        // Vote for times.
        // Everyone votes on an arbitrary time, as long as its within the round time and not in the future
        if (stg_prop.time > cp.time && stg_prop.time - cp.time < conf::cfg.roundtime)
            increment(votes.time, cp.time);

        // Vote for user connections
        for (const std::string &user : cp.users)
            increment(votes.users, user);

        // Vote for user inputs

        // Proposals from stage 0 will have raw inputs in them.
        if (!cp.raw_inputs.empty())
        {
            for (auto &[pubkey, input] : cp.raw_inputs)
            {
                // Hash the pubkey+input.
                std::string str_to_hash;
                str_to_hash.reserve(pubkey.size() + input.size());
                str_to_hash.append(pubkey);
                str_to_hash.append(input);
                std::string hash = crypto::sha_512_hash(str_to_hash, "INP", 3);

                // Vote for the hash.
                increment(votes.inputs, hash);

                // Remember the actual input along with the hash for future use for apply-ledger.
                ctx.possible_inputs.try_emplace(
                    std::move(hash),
                    std::make_pair(pubkey, input));
            }
        }
        // Proposals from stage 1, 2, 3 will have hashed inputs in them.
        else if (!cp.hash_inputs.empty())
        {
            for (const std::string &inputhash : cp.hash_inputs)
                increment(votes.inputs, inputhash);
        }

        // Vote for user outputs

        // Proposals from stage 0 will have raw user outputs in them.
        if (!cp.raw_outputs.empty())
        {
            for (auto &[pubkey, output] : cp.raw_outputs)
            {
                // Hash the pubkey+input.
                std::string str_to_hash;
                str_to_hash.reserve(pubkey.size() + output.size());
                str_to_hash.append(pubkey);
                str_to_hash.append(output);
                std::string hash = crypto::sha_512_hash(str_to_hash, "OUT", 3);

                // Vote for the hash.
                increment<std::string>(votes.outputs, hash);

                // Remember the actual output along with the hash for future use for apply-ledger.
                ctx.possible_outputs.try_emplace(
                    std::move(hash),
                    std::make_pair(pubkey, output));
            }
        }
        // Proposals from stage 1, 2, 3 ill have hashed user outputs in them.
        else if (!cp.hash_outputs.empty())
        {
            for (auto outputhash : cp.hash_outputs)
            {
                increment<std::string>(votes.outputs, outputhash);
            }
        }

        // todo: repeat above for state
    }

    float_t vote_threshold = get_stage_threshold(ctx.stage);

    // todo: check if inputs being proposed by another node are actually spoofed inputs
    // from a user locally connected to this node.

    // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

    // Add user connections which have votes over stage threshold to proposal.
    for (auto &[userpubkey, numvotes] : votes.users)
        if (numvotes >= vote_threshold || (numvotes > 0 && ctx.stage == 1))
            stg_prop.users.emplace(userpubkey);

    // Add inputs which have votes over stage threshold to proposal.
    for (auto &[hash, numvotes] : votes.inputs)
        if (numvotes >= vote_threshold || (numvotes > 0 && ctx.stage == 1))
            stg_prop.hash_inputs.emplace(hash);

    // Add outputs which have votes over stage threshold to proposal.
    for (auto &[hash, numvotes] : votes.outputs)
        if (numvotes >= vote_threshold)
            stg_prop.hash_outputs.emplace(hash);

    // todo:add states which have votes over stage threshold to proposal.

    // time is voted on a simple sorted and majority basis, since there will always be disagreement.
    int32_t largest_vote = 0;
    for (auto &time : votes.time)
    {
        if (time.second > largest_vote)
        {
            largest_vote = time.second;
            stg_prop.time = time.first;
        }
    }

    // we always vote for our current lcl regardless of what other peers are saying
    // if there's a fork condition we will either request history and state from
    // our peers or we will halt depending on level of consensus on the sides of the fork
    stg_prop.lcl = ctx.lcl;

    // Broadcast the stage proposal
    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    p2p::create_msg_from_proposal(msg.builder(), stg_prop);

    LOG_DBG << "Stage (" << std::to_string(ctx.stage)
            << ") Proposed users:" << stg_prop.users.size()
            << " hinputs:" << stg_prop.hash_inputs.size()
            << " houts:" << stg_prop.hash_outputs.size();

    {
        std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
        for (auto &[k, session] : p2p::peer_connections)
            session->send(msg);
    }

    return stg_prop;
}

int8_t get_winning_stage(const std::list<p2p::proposal> &candidate_proposals, vote_counter &votes)
{
    // Stage votes.
    for (const p2p::proposal &cp : candidate_proposals)
    {
        // Vote stages if only proposal lcl is match with node's last consensus lcl
        if (cp.lcl == ctx.lcl)
            increment(votes.stage, cp.stage);

        // todo:vote for lcl checking condtion
    }

    int32_t highest_votes = 0;
    int8_t winning_stage = -1;
    for (const auto [stage, votes] : votes.stage)
    {
        if (votes > highest_votes)
        {
            highest_votes = votes;
            winning_stage = stage;
        }
    }

    return winning_stage;
}

/**
 * Returns the consensus percentage threshold for the specified stage.
 * @param stage The consensus stage [1, 2, 3]
 */
float_t get_stage_threshold(int8_t stage)
{
    switch (stage)
    {
    case 1:
        return cons::STAGE1_THRESHOLD * conf::cfg.unl.size();
    case 2:
        return cons::STAGE2_THRESHOLD * conf::cfg.unl.size();
    case 3:
        return cons::STAGE3_THRESHOLD * conf::cfg.unl.size();
    }
    return -1;
}

void wait_for_proposals(bool reset)
{
    if (reset)
        ctx.stage = 0;

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

/**
 * Finalize the ledger after consensus.
 * @param cons_prop The proposal that reached consensus.
 */
void apply_ledger(const p2p::proposal &cons_prop)
{
    // todo:write lcl.

    // Send any output from the previous consensus round to users.
    for (const std::string &hash : cons_prop.hash_outputs)
    {
        auto itr = ctx.possible_outputs.find(hash);
        bool hashfound = (itr != ctx.possible_outputs.end());
        if (!hashfound)
        {
            // There's no possiblity for this to happen.
            LOG_ERR << "Output required but wasn't in our possible output dict, this will potentially cause desync.";
            // todo: consider fatal
        }
        else
        {
            // Send outputs to users.
            auto &[pubkey, output] = itr->second;
            std::string outputtosend;
            outputtosend.swap(output);

            {
                std::lock_guard<std::mutex> lock(usr::users_mutex);

                // Find the user by session id.
                const std::string sessionid = usr::sessionids[pubkey];
                auto itr = usr::users.find(sessionid);
                if (itr != usr::users.end())
                {
                    const usr::connected_user &user = itr->second;
                    usr::user_outbound_message outmsg(std::move(outputtosend));
                    user.session->send(std::move(outmsg));
                }
            }
        }
    }

    // now we can safely clear our outputs.
    ctx.possible_outputs.empty();

    //todo:check  state against the winning / canonical state
    //and act accordingly (rollback, ask state from peer, etc.)

    //create input to feed to binary contract run

    //todo:remove entries from pending inputs that made their way into a closed ledger
    for (const std::string &hash : cons_prop.hash_inputs)
    {
        auto itr = ctx.possible_inputs.find(hash);
        bool hashfound = (itr != ctx.possible_inputs.end());
        if (!hashfound)
        {
            // There's no possiblity for this to happen.
            LOG_ERR << "input required but wasn't in our possible input dict, this will potentially cause desync";
            // todo: consider fatal
        }
        else
        {
            // Prepare ctx.local_userbuf with user inputs to feed to the contract.
            for (auto &[hash, userinput] : ctx.possible_inputs)
            {
                std::string inputtofeed;
                inputtofeed.swap(userinput.second);

                std::pair<std::string, std::string> bufpair;
                bufpair.first = std::move(inputtofeed);
                ctx.local_userbuf.try_emplace(userinput.first, std::move(bufpair));
            }
            ctx.possible_inputs.empty();
        }
    }

    run_contract_binary(cons_prop.time);
}

void run_contract_binary(time_t time_now)
{
    std::pair<std::string, std::string> hpscbufpair;
    std::unordered_map<std::string, std::pair<std::string, std::string>> nplbufs;

    proc::ContractExecArgs eargs(time_now, ctx.local_userbuf, nplbufs, hpscbufpair);
    proc::exec_contract(eargs);
}

} // namespace cons