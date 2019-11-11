#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../usr/user_input.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../hplog.hpp"
#include "../crypto.hpp"
#include "../proc/proc.hpp"
#include "ledger_handler.hpp"
#include "statemap_handler.hpp"
#include "cons.hpp"

namespace p2pmsg = fbschema::p2pmsg;
namespace jusrmsg = jsonschema::usrmsg;

namespace cons
{

/**
 * Voting thresholds for consensus stages.
 */
constexpr float STAGE1_THRESHOLD = 0.5;
constexpr float STAGE2_THRESHOLD = 0.65;
constexpr float STAGE3_THRESHOLD = 0.8;

consensus_context ctx;

int init()
{
    //set start stage
    ctx.stage = 0;

    //load lcl details from lcl history.
    const ledger_history ldr_hist = load_ledger();
    ctx.led_seq_no = ldr_hist.led_seq_no;
    ctx.lcl = ldr_hist.lcl;

    return 0;
}

void consensus()
{
    // A consensus round consists of 4 stages (0,1,2,3).

    // For a given stage, this function may get visited multiple times due to time-wait conditions.

    // Get the latest current time.
    ctx.time_now = util::get_epoch_milliseconds();

    // Throughout consensus, we move over the incoming proposals collected via the network so far into
    // the candidate proposal set (move and append). This is to have a private working set for the consensus
    // and avoid threading conflicts with network incoming proposals.
    {
        std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.proposals_mutex);
        ctx.candidate_proposals.splice(ctx.candidate_proposals.end(), p2p::ctx.collected_msgs.proposals);
    }

    LOG_DBG << "Started stage " << std::to_string(ctx.stage);
    for (const auto p : ctx.candidate_proposals)
    {
        const bool self = p.pubkey == conf::cfg.pubkey;
        LOG_DBG << "[stage" << std::to_string(p.stage)
                << "] users:" << p.users.size()
                << " hinp:" << p.hash_inputs.size()
                << " hout:" << p.hash_outputs.size()
                << " lcl:" << p.lcl
                << " self:" << self;
    }
    LOG_DBG << "timenow: " << std::to_string(ctx.time_now);

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

        // Broadcast non-unl proposals (NUP) containing inputs from locally connected users.
        broadcast_nonunl_proposal();
        util::sleep(conf::cfg.roundtime / 10);

        // Verify and transfer user inputs from incoming NUPs onto consensus candidate data.
        verify_and_populate_candidate_user_inputs();

        // In stage 0 we create a novel proposal and broadcast it.
        const p2p::proposal stg_prop = create_stage0_proposal();
        broadcast_proposal(stg_prop);
    }
    else // Stage 1, 2, 3
    {
        // Initialize vote counters
        vote_counter votes;

        // check if we're ahead/behind of consensus stage
        bool is_stage_desync, reset_to_stage0;
        uint8_t majority_stage;
        check_majority_stage(is_stage_desync, reset_to_stage0, majority_stage, votes);
        if (is_stage_desync)
        {
            timewait_stage(reset_to_stage0);
            return;
        }

        // check if we're ahead/behind of consensus lcl
        bool is_lcl_desync, should_request_history;
        std::string majority_lcl;
        check_lcl_votes(is_lcl_desync, should_request_history, majority_lcl, votes);

        if (should_request_history)
        {
            //todo:create history request message and request request history from a random peer.
        }
        if (is_lcl_desync)
        {
            const bool should_reset = (ctx.time_now - ctx.novel_proposal_time) < floor(conf::cfg.roundtime / 4);
            //for now we are resetting to stage 0 to avoid possible deadlock situations
            timewait_stage(true);
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
        util::sleep(conf::cfg.roundtime / 100);
    else
        util::sleep(conf::cfg.roundtime / 4);
}

/**
 * Broadcasts any inputs from locally connected users via an NUP.
 * @return 0 for successful broadcast. -1 for failure.
 */
void broadcast_nonunl_proposal()
{
    // Construct NUP.
    p2p::nonunl_proposal nup;

    std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);
    for (auto &[sid, user] : usr::ctx.users)
    {
        std::list<usr::user_submitted_message> usermsgs;
        usermsgs.splice(usermsgs.end(), user.submitted_inputs);

        // We should create an entry for each user pubkey, even if the user has no inputs. This is
        // because this data map will be used to track connected users as well in addition to inputs.
        nup.user_messages.try_emplace(user.pubkey, std::move(usermsgs));
    }

    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_nonunl_proposal(msg.builder(), nup);
    p2p::broadcast_message(msg);

    LOG_DBG << "NUP sent."
            << " users:" << nup.user_messages.size();
}

/**
 * Verifies the user signatures and populate non-expired user inputs from collected
 * non-unl proposals (if any) into consensus candidate data.
 */
void verify_and_populate_candidate_user_inputs()
{
    // Lock the list so any network activity is blocked.
    std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);
    for (const p2p::nonunl_proposal &p : p2p::ctx.collected_msgs.nonunl_proposals)
    {
        for (const auto &[pubkey, umsgs] : p.user_messages)
        {
            // Populate user list.
            ctx.candidate_users.emplace(pubkey);

            for (const usr::user_submitted_message &umsg : umsgs)
            {
                const std::string sig_hash = crypto::get_hash(umsg.sig);

                // Check for duplicate messages using hash of the signature.
                if (ctx.recent_userinput_hashes.try_emplace(sig_hash))
                {
                    // Verify the signature of the message content.
                    if (crypto::verify(umsg.content, umsg.sig, pubkey) == 0)
                    {
                        // TODO: Also verify XRP payment token/AppBill requirements.

                        std::string nonce;
                        std::string input;
                        uint64_t maxledgerseqno;
                        jusrmsg::extract_input_container(nonce, input, maxledgerseqno, umsg.content);

                        // Ignore the input if our ledger has passed the input TTL.
                        if (maxledgerseqno > ctx.led_seq_no)
                        {
                            // Hash is prefixed with the nonce to support user-defined sort order.
                            std::string hash = std::move(nonce);
                            // Append the hash of the message signature to get the final hash.
                            hash.append(sig_hash);

                            ctx.candidate_user_inputs.try_emplace(
                                hash,
                                candidate_user_input(pubkey, std::move(input), maxledgerseqno));
                        }
                    }
                }
                else
                {
                    LOG_DBG << "Duplicate user message.";
                }
            }
        }
    }
    p2p::ctx.collected_msgs.nonunl_proposals.clear();
}

p2p::proposal create_stage0_proposal()
{
    // The proposal we are going to emit in stage 0.
    p2p::proposal stg_prop;
    stg_prop.time = ctx.time_now;
    ctx.novel_proposal_time = ctx.time_now;
    stg_prop.stage = 0;
    stg_prop.lcl = ctx.lcl;

    // Populate the proposal with set of candidate user pubkeys.
    for (const std::string &pubkey : ctx.candidate_users)
        stg_prop.users.emplace(pubkey);

    // We don't need candidate_users anymore, so clear it. It will be repopulated during next censensus round.
    ctx.candidate_users.clear();

    // Populate the proposal with hashes of user inputs.
    for (const auto &[hash, cand_input] : ctx.candidate_user_inputs)
        stg_prop.hash_inputs.emplace(hash);

    // Populate the proposal with hashes of user outputs.
    for (const auto &[hash, cand_output] : ctx.candidate_user_outputs)
        stg_prop.hash_outputs.emplace(hash);

    // todo: set propsal states
    // todo: generate stg_prop hash and check with ctx.novel_proposal, we are sending same proposal again.

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

    // Vote for rest of the proposal fields by looking at candidate proposals.
    for (const p2p::proposal &cp : ctx.candidate_proposals)
    {
        // Vote for times.
        // Everyone votes on an arbitrary time, as long as its within the round time and not in the future.
        if (ctx.time_now > cp.time && (ctx.time_now - cp.time) < conf::cfg.roundtime)
            increment(votes.time, cp.time);

        // Vote for user pubkeys.
        for (const std::string &pubkey : cp.users)
            increment(votes.users, pubkey);

        // Vote for user inputs (hashes). Only vote for the inputs that are in our candidate_inputs set.
        for (const std::string &hash : cp.hash_inputs)
            if (ctx.candidate_user_inputs.count(hash) > 0)
                increment(votes.inputs, hash);

        // Vote for contract outputs (hashes). Only vote for the outputs that are in our candidate_outputs set.
        for (const std::string &hash : cp.hash_outputs)
            if (ctx.candidate_user_outputs.count(hash) > 0)
                increment(votes.outputs, hash);

        // todo: repeat above for state
    }

    const float_t vote_threshold = get_stage_threshold(ctx.stage);

    // todo: check if inputs being proposed by another node are actually spoofed inputs
    // from a user locally connected to this node.

    // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

    // Add user pubkeys which have votes over stage threshold to proposal.
    for (const auto &[pubkey, numvotes] : votes.users)
        if (numvotes >= vote_threshold || (ctx.stage == 1 && numvotes > 0))
            stg_prop.users.emplace(pubkey);

    // Add inputs which have votes over stage threshold to proposal.
    for (const auto &[hash, numvotes] : votes.inputs)
        if (numvotes >= vote_threshold || (ctx.stage == 1 && numvotes > 0))
            stg_prop.hash_inputs.emplace(hash);

    // Add outputs which have votes over stage threshold to proposal.
    for (const auto &[hash, numvotes] : votes.outputs)
        if (numvotes >= vote_threshold)
            stg_prop.hash_outputs.emplace(hash);

    // todo:add states which have votes over stage threshold to proposal.

    // time is voted on a simple sorted and majority basis, since there will always be disagreement.
    int32_t highest_votes = 0;
    for (const auto [time, numvotes] : votes.time)
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
void broadcast_proposal(const p2p::proposal &p)
{
    // In passive mode, we do not send out any propopsals.
    if (conf::cfg.mode == conf::OPERATING_MODE::PASSIVE)
        return;

    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_proposal(msg.builder(), p);
    p2p::broadcast_message(msg);

    LOG_DBG << "Proposed [stage" << std::to_string(p.stage)
            << "] users:" << p.users.size()
            << " hinp:" << p.hash_inputs.size()
            << " hout:" << p.hash_outputs.size();
}

/**
 * Check whether our current stage is ahead or behind of the majority stage.
 */
void check_majority_stage(bool &is_desync, bool &should_reset, uint8_t &majority_stage, vote_counter &votes)
{
    // Stage votes.
    for (const p2p::proposal &cp : ctx.candidate_proposals)
    {
        // Vote stages if only proposal lcl is match with node's last consensus lcl
        if (cp.lcl == ctx.lcl)
            increment(votes.stage, cp.stage);

        // todo:vote for lcl checking condtion
    }

    majority_stage = 0;
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
 * Check our LCL is consistent with the proposals being made by our UNL peers lcl_votes.
 */
void check_lcl_votes(bool &is_desync, bool &should_request_history, std::string &majority_lcl, vote_counter &votes)
{
    // Stage votes.
    int32_t total_lcl_votes = 0;

    for (const p2p::proposal &cp : ctx.candidate_proposals)
    {
        // only consider recent proposals and proposals from previous stage.
        if ((ctx.time_now - cp.timestamp < conf::cfg.roundtime * 4) && (cp.stage == ctx.stage - 1))
        {
            increment(votes.lcl, cp.lcl);
            total_lcl_votes++;
        }
    }

    is_desync = false;
    should_request_history = false;

    if (total_lcl_votes < (0.8 * conf::cfg.unl.size()))
    {
        LOG_DBG << "Not enough peers proposing to perform consensus" << std::to_string(total_lcl_votes) << " needed " << std::to_string(0.8 * conf::cfg.unl.size());
        is_desync = true;
        return;
    }

    int32_t winning_votes = 0;
    for (const auto [lcl, votes] : votes.lcl)
    {
        if (votes > winning_votes)
        {
            winning_votes = votes;
            majority_lcl = lcl;
        }
    }

    double wining_votes_unl_ratio = winning_votes / conf::cfg.unl.size();
    if (wining_votes_unl_ratio < 0.8)
    {
        // potential fork condition.
        LOG_DBG << "No consensus on lcl. Possible fork condition.";
        is_desync = true;
        return;
    }

    //if winning lcl is not matched node lcl,
    //that means vode is not on the consensus ledger.
    //Should request history from a peer.
    if (ctx.lcl != majority_lcl)
    {
        LOG_DBG << "We are not on the consensus ledger, requesting history from a random peer";
        is_desync = true;
        //todo:create history request message and request request history from a random peer.
        should_request_history = true;
        return;
    }
}
/**
 * Returns the consensus percentage threshold for the specified stage.
 * @param stage The consensus stage [1, 2, 3]
 */
float_t get_stage_threshold(const uint8_t stage)
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

void timewait_stage(const bool reset)
{
    if (reset)
        ctx.stage = 0;

    util::sleep(conf::cfg.roundtime / 100);
}

/**
 * Finalize the ledger after consensus.
 * @param cons_prop The proposal that reached consensus.
 */
void apply_ledger(const p2p::proposal &cons_prop)
{
    ctx.led_seq_no++;
    ctx.lcl = cons::save_ledger(cons_prop, ctx.led_seq_no);

    // After the current ledger seq no is updated, we remove any newly expired inputs from candidate set.
    {
        auto itr = ctx.candidate_user_inputs.begin();
        while (itr != ctx.candidate_user_inputs.end())
        {
            if (itr->second.maxledgerseqno <= ctx.led_seq_no)
                ctx.candidate_user_inputs.erase(itr++);
            else
                ++itr;
        }
    }

    // Send any output from the previous consensus round to locally connected users.
    dispatch_user_outputs(cons_prop);

    // todo:check  state against the winning / canonical state
    // and act accordingly (rollback, ask state from peer, etc.)

    // This will hold a list of file blocks that was updated by the contract process.
    // We then feed this information to state tracking logic.
    proc::contract_fblockmap_t updated_blocks;

    proc::contract_bufmap_t useriobufmap;
    feed_inputs_to_contract_bufmap(useriobufmap, cons_prop);

    run_contract_binary(cons_prop.time, useriobufmap, updated_blocks);

    extract_outputs_from_contract_bufmap(useriobufmap);
    update_state_blockmap(updated_blocks);
}

/**
 * Dispatch any consensus-reached outputs to matching users if they are connected to us locally.
 * @param cons_prop The proposal that achieved consensus.
 */
void dispatch_user_outputs(const p2p::proposal &cons_prop)
{
    std::lock_guard<std::mutex> lock(usr::ctx.users_mutex);

    for (const std::string &hash : cons_prop.hash_outputs)
    {
        const auto cu_itr = ctx.candidate_user_outputs.find(hash);
        const bool hashfound = (cu_itr != ctx.candidate_user_outputs.end());
        if (!hashfound)
        {
            LOG_ERR << "Output required but wasn't in our candidate outputs map, this will potentially cause desync.";
            // todo: consider fatal
        }
        else
        {
            // Send matching outputs to locally connected users.

            candidate_user_output &cand_output = cu_itr->second;

            // Find the user session by user pubkey.
            const auto sess_itr = usr::ctx.sessionids.find(cand_output.userpubkey);
            if (sess_itr != usr::ctx.sessionids.end()) // match found
            {
                const auto user_itr = usr::ctx.users.find(sess_itr->second); // sess_itr->second is the session id.
                if (user_itr != usr::ctx.users.end())                        // match found
                {
                    std::string outputtosend;
                    outputtosend.swap(cand_output.output);

                    std::string msg;
                    jusrmsg::create_contract_output_container(msg, outputtosend);

                    const usr::connected_user &user = user_itr->second;
                    user.session->send(usr::user_outbound_message(std::move(msg)));
                }
            }
        }
    }

    // now we can safely clear our candidate outputs.
    ctx.candidate_user_outputs.clear();
}

/**
 * Transfers consensus-reached inputs into the provided contract buf map so it can be fed into the contract process.
 * @param bufmap The contract bufmap which needs to be populated with inputs.
 * @param cons_prop The proposal that achieved consensus.
 */
void feed_inputs_to_contract_bufmap(proc::contract_bufmap_t &bufmap, const p2p::proposal &cons_prop)
{
    // Populate the buf map with all currently connected users regardless of whether they have inputs or not.
    // This is in case the contract wanted to emit some data to a user without needing any input.
    for (const std::string &pubkey : cons_prop.users)
        bufmap.try_emplace(pubkey, proc::contract_iobuf_pair());

    for (const std::string &hash : cons_prop.hash_inputs)
    {
        // For each consensus input hash, we need to find the actual input content to feed the contract.
        const auto itr = ctx.candidate_user_inputs.find(hash);
        const bool hashfound = (itr != ctx.candidate_user_inputs.end());
        if (!hashfound)
        {
            LOG_ERR << "input required but wasn't in our candidate inputs map, this will potentially cause desync.";
            // TODO: consider fatal
        }
        else
        {
            // Populate the input content into the bufmap.

            candidate_user_input &cand_input = itr->second;

            std::string inputtofeed;
            inputtofeed.swap(cand_input.input);

            proc::contract_iobuf_pair &bufpair = bufmap[cand_input.userpubkey];
            bufpair.inputs.push_back(std::move(inputtofeed));

            // Remove the input from the candidate set because we no longer need it.
            ctx.candidate_user_inputs.erase(itr);
        }
    }
}

/**
 * Reads any outputs the contract has produced on the provided buf map and transfers them to candidate outputs
 * for the next consensus round.
 * @param bufmap The contract bufmap containing the outputs produced by the contract.
 */
void extract_outputs_from_contract_bufmap(proc::contract_bufmap_t &bufmap)
{
    for (auto &[pubkey, bufpair] : bufmap)
    {
        if (!bufpair.output.empty())
        {
            std::string output;
            output.swap(bufpair.output);

            const std::string hash = crypto::get_hash(pubkey, output);
            ctx.candidate_user_outputs.try_emplace(
                std::move(hash),
                candidate_user_output(pubkey, std::move(output)));
        }
    }
}

/**
 * Executes the smart contract with the specified time and provided I/O buf maps.
 * @param time_now The time that must be passed on to the contract.
 * @param useriobufmap The contract bufmap which holds user I/O buffers.
 */
void run_contract_binary(const int64_t time_now, proc::contract_bufmap_t &useriobufmap, proc::contract_fblockmap_t &state_updates)
{
    // todo:implement exchange of npl and hpsc bufs
    proc::contract_bufmap_t nplbufmap;
    proc::contract_iobuf_pair hpscbufpair;

    proc::exec_contract(
        proc::contract_exec_args(time_now, useriobufmap, nplbufmap, hpscbufpair, state_updates));
}

/**
 * Increment voting table counter.
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

} // namespace cons