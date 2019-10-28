#include <math.h>
#include <thread>
#include <flatbuffers/flatbuffers.h>
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../hplog.hpp"
#include "../crypto.hpp"
#include "../proc.hpp"
#include "cons.hpp"

namespace p2pmsg = fbschema::p2pmsg;

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
void increment(std::map<T, int32_t> &counter, const T &candidate)
{
    if (counter.count(candidate))
        counter[candidate]++;
    else
        counter.try_emplace(candidate, 1);
}

void consensus()
{
    // A consensus round consists of 4 stages (0,1,2,3).

    // For a given stage, this function may get visited multiple times due to time-wait conditions.

    // Get the latest current time.
    ctx.time_now = util::get_epoch_milliseconds();

    // Throughout consensus, we move over the incoming proposals collected via the network so far into
    // the candidate proposal set (move and append). This is to have a private working set for the consensus and avoid
    // threading conflicts with network incoming proposals.
    {
        std::lock_guard<std::mutex> lock(p2p::collected_msgs.proposals_mutex);
        ctx.candidate_proposals.splice(ctx.candidate_proposals.end(), p2p::collected_msgs.proposals);
    }

    if (ctx.stage == 0)
    {
        // Stage 0 means begining of a consensus round.

        {
            // Remove any useless candidate proposals so we'll have a cleaner proposal set to look at
            // when we transition to stage 1.
            auto itr = ctx.candidate_proposals.begin();
            while (itr != ctx.candidate_proposals.end())
            {
                // Remove any proposal from previous round's stage 3.
                // Remove any proposal from self (pubkey match).
                // todo: check the state of these to ensure we're running consensus ledger
                if (itr->stage == 3 || conf::cfg.pubkey == itr->pubkey)
                    ctx.candidate_proposals.erase(itr++);
                else
                    ++itr;
            }
        }

        // Transfer connected user data onto consensus candidate data.
        populate_candidate_users_and_inputs();

        // In stage 0 we create a novel proposal and broadcast it.
        const p2p::proposal stg_prop = create_stage0_proposal();
        if (broadcast_proposal(stg_prop) != 0)
        {
            // No peers to broadcast stage0 proposal (not even self). So we wait and try stage 0 again.
            timewait_stage(true);
            return;
        }
    }
    else // Stage 1, 2, 3
    {
        // Initialize vote counters
        vote_counter votes;

        // check if we're ahead/behind of consensus
        bool is_desync, reset_to_stage0;
        int8_t majority_stage;
        check_majority_stage(is_desync, reset_to_stage0, majority_stage, votes);
        if (is_desync)
        {
            timewait_stage(reset_to_stage0);
            return;
        }

        // In stage 1, 2, 3 we vote for incoming proposals and promote winning votes based on thresholds.
        const p2p::proposal stg_prop = create_stage123_proposal(votes);
        broadcast_proposal(stg_prop);

        // Remove all candidate proposals that are behind our current stage.
        auto itr = ctx.candidate_proposals.begin();
        while (itr != ctx.candidate_proposals.end())
        {
            if (itr->stage < ctx.stage)
                ctx.candidate_proposals.erase(itr++);
            else
                ++itr;
        }

        if (ctx.stage == 3)
        {
            apply_ledger(stg_prop);

            // We have finished a consensus round (all 4 stages).
            LOG_DBG << "****Stage 3 consensus reached****";
        }
    }

    // We have finished a consensus stage.

    // Transition to next stage.
    ctx.stage = (ctx.stage + 1) % 4;

    // after a stage 0 novel proposal we will just busy wait for proposals
    if (ctx.stage == 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(conf::cfg.roundtime / 100));
    else
        std::this_thread::sleep_for(std::chrono::milliseconds(conf::cfg.roundtime / 4));
}

/**
 * Populate connected users and their inputs (if any) into consensus candidate data.
 */
void populate_candidate_users_and_inputs()
{
    // Lock the connected user list until we do this operation.
    std::lock_guard<std::mutex> lock(usr::users_mutex);
    for (auto &[sid, con_user] : usr::users)
    {
        // Populate the user into candidate user inputs map.
        // We do this regardless of whether the user has any inputs or not.

        std::list<util::hash_buffer> &inplist = ctx.candidate_users[con_user.pubkey];

        // Transfer the connected user's inputs (if any) to the candidate user's inputs list.
        inplist.splice(inplist.end(), con_user.inputs);
    }
}

p2p::proposal create_stage0_proposal()
{
    // The proposal we are going to emit in stage 0.
    p2p::proposal stg_prop;
    stg_prop.time = ctx.time_now;
    ctx.novel_proposal_time = ctx.time_now;
    stg_prop.stage = 0;
    stg_prop.lcl = ctx.lcl;

    // Populate the poposal with users list (user pubkey list) and their inputs.

    for (auto [pubkey, inputs] : ctx.candidate_users)
    {
        // Add all the user connections we host.
        stg_prop.users.emplace(pubkey);

        // Add all their pending inputs.
        if (!inputs.empty())
        {
            std::vector<util::hash_buffer> inpvec;
            for (util::hash_buffer &hashbuf : inputs)
                inpvec.push_back(hashbuf); // Copy all hashbufs from candidate inputs into the proposal.

            stg_prop.raw_inputs.emplace(pubkey, std::move(inpvec));
        }
    }

    // Populate the stg_prop with any contract outputs from previous round's stage 3.
    for (auto &[pubkey, bufpair] : ctx.useriobufmap)
    {
        if (!bufpair.output.empty())
        {
            std::string rawoutput;
            rawoutput.swap(bufpair.output);

            stg_prop.raw_outputs.try_emplace(pubkey, util::hash_buffer(rawoutput, pubkey));
        }
    }
    ctx.useriobufmap.clear();

    // todo: set propsal states
    // todo: generate stg_prop hash and check with ctx.novel_proposal, we are sending same stg_prop again.

    return stg_prop;
}

p2p::proposal create_stage123_proposal(vote_counter &votes)
{
    // The proposal to be emited at the end of this stage.
    p2p::proposal stg_prop;
    stg_prop.stage = ctx.stage;

    // we always vote for our current lcl regardless of what other peers are saying
    // if there's a fork condition we will either request history and state from
    // our peers or we will halt depending on level of consensus on the sides of the fork
    stg_prop.lcl = ctx.lcl;

    //todo:check lcl votes and wait for proposals

    // Vote for rest of the proposal fields by looking at candidate proposals.
    for (const p2p::proposal &cp : ctx.candidate_proposals)
    {
        // Vote for times.
        // Everyone votes on an arbitrary time, as long as its within the round time and not in the future
        if (ctx.time_now > cp.time && (ctx.time_now - cp.time) < conf::cfg.roundtime)
            increment(votes.time, cp.time);

        // Vote for user connections
        for (const std::string &user : cp.users)
            increment(votes.users, user);

        // Vote for user inputs

        // Proposals from stage 0 will have raw inputs (and their hashes) in them.
        if (!cp.raw_inputs.empty())
        {
            for (auto &[pubkey, inputs] : cp.raw_inputs)
            {
                // Vote for the input hash.
                for (util::hash_buffer input : inputs)
                {
                    increment(votes.inputs, input.hash);

                    std::string inputbuffer;
                    inputbuffer.swap(input.buffer);
                    // Remember the actual input along with the hash for future use for apply-ledger.
                    ctx.possible_inputs.try_emplace(input.hash, std::make_pair(pubkey, inputbuffer));
                }
            }
        }
        // Proposals from stage 1, 2, 3 will have only input hashes in them.
        else if (!cp.hash_inputs.empty())
        {
            for (const std::string &inputhash : cp.hash_inputs)
                increment(votes.inputs, inputhash);
        }

        // Vote for contract outputs

        // Proposals from stage 0 will have raw user outputs in them.
        if (!cp.raw_outputs.empty())
        {
            for (auto [pubkey, output] : cp.raw_outputs)
            {
                // Vote for the hash.
                increment<std::string>(votes.outputs, output.hash);

                std::string outputbuf;
                outputbuf.swap(output.buffer);

                // Remember the actual output along with the hash for future use for apply-ledger and sending back to user.
                ctx.possible_outputs.try_emplace(output.hash, std::make_pair(pubkey, outputbuf));
            }
        }
        // Proposals from stage 1, 2, 3 will have hashed user outputs in them.
        else if (!cp.hash_outputs.empty())
        {
            for (auto outputhash : cp.hash_outputs)
                increment<std::string>(votes.outputs, outputhash);
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
    int32_t highest_votes = 0;
    for (auto [time, numvotes] : votes.time)
    {
        if (numvotes > highest_votes)
        {
            highest_votes = numvotes;
            stg_prop.time = time;
        }
    }

    return stg_prop;
}

/**
 * Broadcasts the given proposal to all connected peers.
 * @return 0 on success. -1 if no peers to broadcast.
 */
int broadcast_proposal(const p2p::proposal &p)
{
    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_proposal(msg.builder(), p);

    {
        //Broadcast while locking the peer_connections.
        std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);

        if (p2p::peer_connections.size() == 0)
        {
            LOG_DBG << "No peers to broadcast";
            return -1;
        }

        for (auto &[k, session] : p2p::peer_connections)
            session->send(msg);
    }

    LOG_DBG << "Proposed [stage" << std::to_string(p.stage)
            << "] users:" << p.users.size()
            << " rinp:" << p.raw_inputs.size()
            << " hinp:" << p.hash_inputs.size()
            << " rout:" << p.raw_outputs.size()
            << " hout:" << p.hash_outputs.size();

    return 0;
}

/**
 * Check whether our current stage is ahead or behind of the majority stage.
 */
void check_majority_stage(bool &is_desync, bool &should_reset, int8_t &majority_stage, vote_counter &votes)
{
    // Stage votes.
    for (const p2p::proposal &cp : ctx.candidate_proposals)
    {
        // Vote stages if only proposal lcl is match with node's last consensus lcl
        if (cp.lcl == ctx.lcl)
            increment(votes.stage, cp.stage);

        // todo:vote for lcl checking condtion
    }

    majority_stage = -1;
    is_desync = false;

    int32_t highest_votes = 0;
    for (const auto [stage, votes] : votes.stage)
    {
        if (votes > highest_votes)
        {
            highest_votes = votes;
            majority_stage = stage;
        }
    }

    if (majority_stage < ctx.stage - 1)
    {
        should_reset = (ctx.time_now - ctx.novel_proposal_time) < floor(conf::cfg.roundtime / 4);
        is_desync = true;

        LOG_DBG << "Stage desync (Reset:" << should_reset << "). Node stage:" << std::to_string(ctx.stage)
                << " is ahead of majority stage:" << std::to_string(majority_stage);
    }
    else if (majority_stage > ctx.stage - 1)
    {
        should_reset = true;
        is_desync = true;

        LOG_DBG << "Stage desync (Reset:" << should_reset << "). Node stage:" << std::to_string(ctx.stage)
                << " is behind majority stage:" << std::to_string(majority_stage);
    }
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

void timewait_stage(bool reset)
{
    if (reset)
        ctx.stage = 0;

    std::this_thread::sleep_for(std::chrono::milliseconds(conf::cfg.roundtime / 100));
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
            // Prepare ctx.useriobufmap with user inputs to feed to the contract.

            const std::string &pubkey = itr->second.first;
            std::string rawinput = itr->second.second;

            std::string inputtofeed;
            inputtofeed.swap(rawinput);

            proc::contract_iobuf_pair &bufpair = ctx.useriobufmap[pubkey];
            bufpair.inputs.push_back(std::move(inputtofeed));
        }
    }
    ctx.possible_inputs.clear();

    run_contract_binary(cons_prop.time);

    // Remove entries from candidate inputs that made their way into a closed ledger
    auto cu_itr = ctx.candidate_users.begin();
    while (cu_itr != ctx.candidate_users.end())
    {
        // Delete any ledger inputs for this user.
        std::list<util::hash_buffer> &inputs = cu_itr->second;
        auto inp_itr = inputs.begin();
        while (inp_itr != inputs.end())
        {
            // Delete the input from the list, if it was part of consensus proposal.
            if (cons_prop.hash_inputs.count(inp_itr->hash))
                inputs.erase(inp_itr++);
            else
                ++inp_itr;
        }

        // Delete the user from the list if there are no more unprocessed inputs.
        if (cu_itr->second.empty())
            ctx.candidate_users.erase(cu_itr++);
        else
            ++cu_itr;
    }
}

void run_contract_binary(int64_t time_now)
{
    // todo:implement proper data structures to exchange npl and hpsc bufs
    proc::contract_bufmap_t nplbufs;
    proc::contract_iobuf_pair hpscbufpair;

    proc::ContractExecArgs eargs(time_now, ctx.useriobufmap, nplbufs, hpscbufpair);
    proc::exec_contract(eargs);
}

} // namespace cons