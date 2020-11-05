#include "pchheader.hpp"
#include "conf.hpp"
#include "usr/usr.hpp"
#include "usr/user_input.hpp"
#include "p2p/p2p.hpp"
#include "msg/fbuf/p2pmsg_helpers.hpp"
#include "msg/usrmsg_parser.hpp"
#include "msg/usrmsg_common.hpp"
#include "p2p/peer_session_handler.hpp"
#include "hplog.hpp"
#include "crypto.hpp"
#include "sc.hpp"
#include "hpfs/h32.hpp"
#include "hpfs/hpfs.hpp"
#include "state/state_common.hpp"
#include "state/state_sync.hpp"
#include "ledger.hpp"
#include "consensus.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace consensus
{

    /**
     * Voting thresholds for consensus stages.
     */
    constexpr float STAGE1_THRESHOLD = 0.5;
    constexpr float STAGE2_THRESHOLD = 0.65;
    constexpr float STAGE3_THRESHOLD = 0.8;
    constexpr float MAJORITY_THRESHOLD = 0.8;

    consensus_context ctx;
    bool init_success = false;

    int init()
    {
        // We allocate 1/3 of roundtime for each stage (there are 3 stages: 1,2,3)
        ctx.stage_time = conf::cfg.roundtime / 3;
        ctx.stage_reset_wait_threshold = conf::cfg.roundtime / 10;

        ctx.contract_ctx.args.state_dir = conf::ctx.state_rw_dir;
        ctx.contract_ctx.args.readonly = false;

        // Starting consensus processing thread.
        ctx.consensus_thread = std::thread(run_consensus);

        init_success = true;
        return 0;
    }

    /**
     * Cleanup any resources.
     */
    void deinit()
    {
        if (init_success)
        {
            // Making the consensus while loop stop.
            ctx.is_shutting_down = true;

            // Stop the contract if running.
            sc::stop(ctx.contract_ctx);

            // Joining consensus processing thread.
            if (ctx.consensus_thread.joinable())
                ctx.consensus_thread.join();
        }
    }

    /**
     * Joins the consensus processing thread.
     */
    void wait()
    {
        ctx.consensus_thread.join();
    }

    void run_consensus()
    {
        util::mask_signal();

        LOG_INFO << "Consensus processor started.";

        while (!ctx.is_shutting_down)
        {
            if (consensus() == -1)
            {
                LOG_ERROR << "Consensus thread exited due to an error.";
                break;
            }
        }

        LOG_INFO << "Consensus processor stopped.";
    }

    int consensus()
    {
        // A consensus round consists of 3 stages (1,2,3).
        // Stage 3 is the last stage AND it also provides entry point for next round stage 1.
        // For a given stage, this function may get visited multiple times due to time-wait conditions.

        uint64_t stage_start = 0;
        if (!wait_and_proceed_stage(stage_start))
            return 0; // This means the stage has been reset.

        // Throughout consensus, we continously update and prune the candidate proposals for newly
        // arived ones and expired ones.
        revise_candidate_proposals();

        LOG_DEBUG << "Started stage " << std::to_string(ctx.stage);

        // We consider stage start time as the current discreet time throughout the stage.
        ctx.time_now = stage_start;

        // Get current lcl and state.
        std::string lcl = ledger::ctx.get_lcl();
        uint64_t lcl_seq_no = ledger::ctx.get_seq_no();
        hpfs::h32 state = state_common::ctx.get_state();
        vote_counter votes;

        if (ctx.stage == 1)
        {
            if (is_in_sync(lcl, votes))
            {
                // If we are in sync, vote and broadcast the winning votes to next stage.
                const p2p::proposal p = create_stage_proposal(STAGE1_THRESHOLD, votes, lcl, state);
                broadcast_proposal(p);
            }
        }
        else if (ctx.stage == 2)
        {
            if (is_in_sync(lcl, votes))
            {
                // If we are in sync, vote and broadcast the winning votes to next stage.
                const p2p::proposal p = create_stage_proposal(STAGE2_THRESHOLD, votes, lcl, state);
                broadcast_proposal(p);
            }

            // In stage 2, broadcast non-unl proposal (NUP) containing inputs from locally connected users.
            // This will be captured and verified at the end of stage 3.
            broadcast_nonunl_proposal();
        }
        else if (ctx.stage == 3)
        {
            if (is_in_sync(lcl, votes))
            {
                // If we are in sync, vote and get the final winning votes.
                // This is the consensus proposal which makes it into the ledger and contract execution
                const p2p::proposal p = create_stage_proposal(STAGE3_THRESHOLD, votes, lcl, state);

                // Update the ledger and execute the contract using the consensus proposal.
                if (update_ledger_and_execute_contract(p, lcl, state) == -1)
                    LOG_ERROR << "Error occured in Stage 3 consensus execution.";
            }

            // Prepare for next round by sending NEW-ROUND PROPOSAL.
            // At the end of stage 3, we broadcast the "new round" proposal which is subjected
            // to voting in next round stage 1.

            // Prepare the consensus candidate user inputs that we have acumulated so far. (We receive them periodically via NUPs)
            // The candidate inputs will be included in the new round proposal.
            verify_and_populate_candidate_user_inputs(lcl_seq_no);

            const p2p::proposal new_round_prop = create_new_round_proposal(lcl, state);
            broadcast_proposal(new_round_prop);
        }

        // We have finished a consensus stage. Transition to next stage. (if at stage 3 go to next round stage 1)
        ctx.stage = (ctx.stage < 3) ? (ctx.stage + 1) : 1;
        return 0;
    }

    bool is_in_sync(std::string_view lcl, vote_counter &votes)
    {
        // Check if we're ahead/behind of consensus lcl.
        bool is_lcl_desync = false;
        std::string majority_lcl;
        if (check_lcl_votes(is_lcl_desync, majority_lcl, votes, lcl))
        {
            // We proceed further only if lcl check was success (meaning lcl check could be reliably performed).

            // State lcl sync if we are out-of-sync with majority lcl.
            if (is_lcl_desync)
            {
                conf::change_operating_mode(conf::OPERATING_MODE::OBSERVER);
                ledger::set_sync_target(majority_lcl);
            }

            // Check our state with majority state.
            bool is_state_desync = false;
            hpfs::h32 majority_state = hpfs::h32_empty;
            check_state_votes(is_state_desync, majority_state, votes);

            // Start state sync if we are out-of-sync with majority state.
            if (is_state_desync)
            {
                conf::change_operating_mode(conf::OPERATING_MODE::OBSERVER);
                state_sync::set_target(majority_state);
            }

            // Proceed further only if both lcl and state are in sync with majority.
            if (!is_lcl_desync && !is_state_desync)
            {
                conf::change_operating_mode(conf::OPERATING_MODE::PROPOSER);
                return true;
            }
        }

        return false;
    }

    /**
     * Moves proposals collected from the network into candidate proposals and
     * cleans up any outdated proposals from the candidate set.
     */
    void revise_candidate_proposals()
    {
        // Move over the network proposal collection into a local list. This is to have a private working
        // set for candidate parsing and avoid threading conflicts with network incoming proposals.
        std::list<p2p::proposal> collected_proposals;
        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.collected_msgs.proposals_mutex);
            collected_proposals.splice(collected_proposals.end(), p2p::ctx.collected_msgs.proposals);
        }

        // Move collected propsals to candidate set of proposals.
        // Add propsals of new nodes and replace proposals from old nodes to reflect current status of nodes.
        for (const auto &proposal : collected_proposals)
        {
            auto prop_itr = ctx.candidate_proposals.find(proposal.pubkey);
            if (prop_itr != ctx.candidate_proposals.end())
            {
                ctx.candidate_proposals.erase(prop_itr);
                ctx.candidate_proposals.emplace(proposal.pubkey, std::move(proposal));
            }
            else
            {
                ctx.candidate_proposals.emplace(proposal.pubkey, std::move(proposal));
            }
        }

        // Prune any outdated proposals.
        auto itr = ctx.candidate_proposals.begin();
        while (itr != ctx.candidate_proposals.end())
        {
            const p2p::proposal &cp = itr->second;
            const uint64_t time_diff = (ctx.time_now > cp.sent_timestamp) ? (ctx.time_now - cp.sent_timestamp) : 0;
            const int8_t stage_diff = ctx.stage - cp.stage;

            // only consider recent proposals and proposals from previous stage and current stage.
            const bool keep_candidate = (time_diff < (conf::cfg.roundtime * 4)) && (stage_diff == -3 || stage_diff <= 1);
            LOG_DEBUG << (keep_candidate ? "Prop--->" : "Erased")
                      << " [s" << std::to_string(cp.stage)
                      << "] u/i/o:" << cp.users.size()
                      << "/" << cp.hash_inputs.size()
                      << "/" << cp.hash_outputs.size()
                      << " ts:" << std::to_string(cp.time)
                      << " lcl:" << cp.lcl.substr(0, 15)
                      << " state:" << cp.state
                      << " [from:" << ((cp.pubkey == conf::cfg.pubkey) ? "self" : util::get_hex(cp.pubkey, 1, 5)) << "]";

            if (keep_candidate)
                ++itr;
            else
                ctx.candidate_proposals.erase(itr++);
        }
    }

    /**
     * Syncrhonise the stage/round time for fixed intervals and reset the stage.
     * @return True if consensus can proceed in the current round. False if stage is reset.
     */
    bool wait_and_proceed_stage(uint64_t &stage_start)
    {
        // Here, nodes try to synchronise nodes stages using network clock.
        // We devide universal time to windows of equal size of roundtime. Each round must be synced with the
        // start of a window.

        const uint64_t now = util::get_epoch_milliseconds();

        // Rrounds are discreet windows of roundtime.
        // This gets the start time of current round window. Stage 1 must start in the next round window.
        const uint64_t current_round_start = (((uint64_t)(now / conf::cfg.roundtime)) * conf::cfg.roundtime);

        if (ctx.stage == 1)
        {
            // Stage 1 must start in the next round window.
            stage_start = current_round_start + conf::cfg.roundtime;
            const int64_t to_wait = stage_start - now;

            LOG_DEBUG << "Waiting " << std::to_string(to_wait) << "ms for next round stage 1";
            util::sleep(to_wait);
            return true;
        }
        else
        {
            stage_start = current_round_start + ((ctx.stage - 1) * ctx.stage_time);

            // Compute stage time wait.
            // Node wait between stages to collect enough proposals from previous stages from other nodes.
            const int64_t to_wait = stage_start - now;

            // If a node doesn't have enough time (eg. due to network delay) to recieve/send reliable stage proposals for next stage,
            // it will join in next round. Otherwise it will continue particapating in this round.
            if (to_wait < ctx.stage_reset_wait_threshold) //todo: self claculating/adjusting network delay
            {
                LOG_DEBUG << "Missed stage " << std::to_string(ctx.stage) << " window. Resetting to stage 1";
                ctx.stage = 1;
                return false;
            }
            else
            {
                LOG_DEBUG << "Waiting " << std::to_string(to_wait) << "ms for stage " << std::to_string(ctx.stage);
                util::sleep(to_wait);
                return true;
            }
        }
    }

    /**
     * Broadcasts any inputs from locally connected users via an NUP.
     */
    void broadcast_nonunl_proposal()
    {
        p2p::nonunl_proposal nup;

        {
            // Populate users and inputs to the NUP within user lock.
            std::scoped_lock lock(usr::ctx.users_mutex);

            if (usr::ctx.users.empty())
                return;

            // Construct NUP.
            for (auto &[sid, user] : usr::ctx.users)
            {
                std::list<usr::user_input> user_inputs;
                user_inputs.splice(user_inputs.end(), user.submitted_inputs);

                // We should create an entry for each user pubkey, even if the user has no inputs. This is
                // because this data map will be used to track connected users as well in addition to inputs.
                nup.user_inputs.try_emplace(user.pubkey, std::move(user_inputs));
            }
        }

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_nonunl_proposal(fbuf, nup);
        p2p::broadcast_message(fbuf, true);

        LOG_DEBUG << "NUP sent."
                  << " users:" << nup.user_inputs.size();
    }

    /**
     * Equeue npl messages to the npl messages queue.
     * @param npl_msg Constructed npl message.
     * @return Returns true if enqueue is success otherwise false.
     */
    bool push_npl_message(p2p::npl_message &npl_msg)
    {
        return ctx.contract_ctx.args.npl_messages.try_enqueue(npl_msg);
    }

    /**
     * Verifies the user signatures and populate non-expired user inputs from collected
     * non-unl proposals (if any) into consensus candidate data.
     */
    void verify_and_populate_candidate_user_inputs(const uint64_t lcl_seq_no)
    {
        // Move over NUPs collected from the network into a local list.
        std::list<p2p::nonunl_proposal> collected_nups;
        {
            std::scoped_lock lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);
            collected_nups.splice(collected_nups.end(), p2p::ctx.collected_msgs.nonunl_proposals);
        }

        // Prepare merged list of users with each user's inputs grouped under the user.
        // Key: user pubkey, Value: List of inputs from the user.
        std::unordered_map<std::string, std::list<usr::user_input>> input_groups;
        for (p2p::nonunl_proposal &p : collected_nups)
        {
            for (auto &[pubkey, umsgs] : p.user_inputs)
            {
                // Move any user inputs from each NUP over to the grouped inputs under the user pubkey.
                std::list<usr::user_input> &input_list = input_groups[pubkey];
                input_list.splice(input_list.end(), umsgs);
            }
        }
        collected_nups.clear();

        // Maintains users and any input-acceptance responses we should send to them.
        // Key: user pubkey. Value: List of [user-protocol, msg-sig, reject-reason] tuples.
        std::unordered_map<std::string, std::list<std::tuple<const util::PROTOCOL, const std::string, const char *>>> responses;

        for (const auto &[pubkey, umsgs] : input_groups)
        {
            // Populate user list with this user's pubkey.
            ctx.candidate_users.emplace(pubkey);

            // Keep track of total input length to verify against remaining balance.
            // We only process inputs in the submitted order that can be satisfied with the remaining account balance.
            size_t total_input_len = 0;
            bool appbill_balance_exceeded = false;
            util::rollover_hashset recent_user_input_hashes(200);

            for (const usr::user_input &umsg : umsgs)
            {
                const char *reject_reason = NULL;

                if (appbill_balance_exceeded)
                {
                    reject_reason = msg::usrmsg::REASON_APPBILL_BALANCE_EXCEEDED;
                }
                else
                {
                    std::string hash, input;
                    uint64_t max_lcl_seqno;
                    reject_reason = usr::validate_user_input_submission(pubkey, umsg, lcl_seq_no, total_input_len, recent_user_input_hashes,
                                                                        hash, input, max_lcl_seqno);

                    if (reject_reason == NULL)
                    {
                        // No reject reason means we should go ahead and subject the input to consensus.
                        ctx.candidate_user_inputs.try_emplace(
                            hash,
                            candidate_user_input(pubkey, std::move(input), max_lcl_seqno));
                    }
                    else if (reject_reason == msg::usrmsg::REASON_APPBILL_BALANCE_EXCEEDED)
                    {
                        // Abandon processing further inputs from this user when we find out
                        // an input cannot be processed with the account balance.
                        appbill_balance_exceeded = true;
                    }
                }

                responses[pubkey].push_back(std::tuple<const util::PROTOCOL, const std::string, const char *>(umsg.protocol, umsg.sig, reject_reason));
            }
        }

        input_groups.clear();

        {
            // Lock the user sessions.
            std::scoped_lock lock(usr::ctx.users_mutex);

            for (auto &[pubkey, user_responses] : responses)
            {
                // Locate this user's socket session.
                const auto user_itr = usr::ctx.users.find(pubkey);
                if (user_itr != usr::ctx.users.end())
                {
                    // Send the request status result if this user is connected to us.
                    for (auto &resp : user_responses)
                    {
                        // resp: 0=protocl, 1=msg sig, 2=reject reason.
                        msg::usrmsg::usrmsg_parser parser(std::get<0>(resp));
                        const std::string &msg_sig = std::get<1>(resp);
                        const char *reject_reason = std::get<2>(resp);

                        usr::send_input_status(parser,
                                               user_itr->second.session,
                                               reject_reason == NULL ? msg::usrmsg::STATUS_ACCEPTED : msg::usrmsg::STATUS_REJECTED,
                                               reject_reason == NULL ? "" : reject_reason,
                                               msg_sig);
                    }
                }
            }
        }
    }

    p2p::proposal create_new_round_proposal(std::string_view lcl, hpfs::h32 state)
    {
        // The proposal we are going to emit at the end of stage 3 after ledger update.
        // This is the proposal that stage 1 votes on.
        p2p::proposal stg_prop;
        stg_prop.time = ctx.time_now;
        stg_prop.stage = 0;
        stg_prop.lcl = lcl;
        stg_prop.state = state;

        // Populate the proposal with set of candidate user pubkeys.
        stg_prop.users.swap(ctx.candidate_users);

        // Populate the proposal with hashes of user inputs.
        for (const auto &[hash, cand_input] : ctx.candidate_user_inputs)
            stg_prop.hash_inputs.emplace(hash);

        // Populate the proposal with hashes of user outputs.
        for (const auto &[hash, cand_output] : ctx.candidate_user_outputs)
            stg_prop.hash_outputs.emplace(hash);

        // todo: generate stg_prop hash and check with ctx.novel_proposal, we are sending same proposal again.

        return stg_prop;
    }

    p2p::proposal create_stage_proposal(const float_t vote_threshold, vote_counter &votes, std::string_view lcl, hpfs::h32 state)
    {
        // The proposal to be emited at the end of this stage.
        p2p::proposal stg_prop;
        stg_prop.stage = ctx.stage;
        stg_prop.state = state;

        // we always vote for our current lcl and state regardless of what other peers are saying
        // if there's a fork condition we will either request history and state from
        // our peers or we will halt depending on level of consensus on the sides of the fork.
        stg_prop.lcl = lcl;

        // Vote for rest of the proposal fields by looking at candidate proposals.
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            // Vote for times.
            // Everyone votes on an arbitrary time, as long as it's not in the future and within the round time.
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
        }

        const float_t required_votes = vote_threshold * conf::cfg.unl.size();

        // todo: check if inputs being proposed by another node are actually spoofed inputs
        // from a user locally connected to this node.

        // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

        // Add user pubkeys which have votes over stage threshold to proposal.
        for (const auto &[pubkey, numvotes] : votes.users)
            if (numvotes >= required_votes || (ctx.stage == 1 && numvotes > 0))
                stg_prop.users.emplace(pubkey);

        // Add inputs which have votes over stage threshold to proposal.
        for (const auto &[hash, numvotes] : votes.inputs)
            if (numvotes >= required_votes || (ctx.stage == 1 && numvotes > 0))
                stg_prop.hash_inputs.emplace(hash);

        // Add outputs which have votes over stage threshold to proposal.
        for (const auto &[hash, numvotes] : votes.outputs)
            if (numvotes >= required_votes)
                stg_prop.hash_outputs.emplace(hash);

        // time is voted on a simple sorted (highest to lowest) and majority basis, since there will always be disagreement.
        int32_t highest_time_vote = 0;
        for (auto itr = votes.time.rbegin(); itr != votes.time.rend(); ++itr)
        {
            const uint64_t time = itr->first;
            const int32_t numvotes = itr->second;

            if (numvotes > highest_time_vote)
            {
                highest_time_vote = numvotes;
                stg_prop.time = time;
            }
        }

        return stg_prop;
    }

    /**
     * Broadcasts the given proposal to all connected peers if in PROPOSER mode. Otherwise
     * only send to self in OBSERVER mode.
     * @return 0 on success. -1 if no peers to broadcast.
     */
    void broadcast_proposal(const p2p::proposal &p)
    {
        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_proposal(fbuf, p);

        // In observer mode, we only send out the proposal to ourselves.
        if (conf::cfg.current_mode == conf::OPERATING_MODE::OBSERVER)
            p2p::send_message_to_self(fbuf);
        else
            p2p::broadcast_message(fbuf, true);

        LOG_DEBUG << "Proposed u/i/o:" << p.users.size()
                  << "/" << p.hash_inputs.size()
                  << "/" << p.hash_outputs.size()
                  << " ts:" << std::to_string(p.time)
                  << " lcl:" << p.lcl.substr(0, 15)
                  << " state:" << p.state;
    }

    /**
     * Check whether our lcl is consistent with the proposals being made by our UNL peers lcl votes.
     * @param is_desync Indicates whether our lcl is out-of-sync with majority lcl. Only valid if this method returns True.
     * @param majority_lcl The majority lcl based on the votes received. Only valid if this method returns True.
     * @param votes Vote counter for this stage.
     * @param lcl Our lcl.
     * @return True if majority lcl could be calculated reliably. False if lcl check failed due to unreliable votes.
     */
    bool check_lcl_votes(bool &is_desync, std::string &majority_lcl, vote_counter &votes, std::string_view lcl)
    {
        int32_t total_lcl_votes = 0;

        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.lcl, cp.lcl);
            total_lcl_votes++;
        }

        if (total_lcl_votes < (MAJORITY_THRESHOLD * conf::cfg.unl.size()))
        {
            LOG_DEBUG << "Not enough peers proposing to perform consensus. votes:" << total_lcl_votes << " needed:" << ceil(MAJORITY_THRESHOLD * conf::cfg.unl.size());
            return false;
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

        // If winning lcl is not matched with our lcl, that means we are not on the consensus ledger.
        // We should request history straight away.
        if (lcl != majority_lcl)
        {
            LOG_DEBUG << "We are not on the consensus ledger,  we must request history from a peer.";
            is_desync = true;
            return true;
        }
        // Check wheher there are good enough winning votes.
        else if (winning_votes < MAJORITY_THRESHOLD * ctx.candidate_proposals.size())
        {
            // potential fork condition.
            LOG_DEBUG << "No consensus on lcl. Possible fork condition. won:" << winning_votes << " total:" << ctx.candidate_proposals.size();
            return false;
        }
        else
        {
            // Reaching here means we have reliable amount of lcl votes and our lcl match with majority lcl.
            is_desync = false;
            return true;
        }
    }

    /**
     * Check state against the winning and canonical state
     * @param votes The voting table.
     */
    void check_state_votes(bool &is_desync, hpfs::h32 &majority_state, vote_counter &votes)
    {
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.state, cp.state);
        }

        int32_t winning_votes = 0;
        for (const auto [state, votes] : votes.state)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_state = state;
            }
        }

        is_desync = (state_common::ctx.get_state() != majority_state);
    }

    /**
     * Update the ledger and execute the contract after consensus.
     * @param cons_prop The proposal that reached consensus.
     */
    int update_ledger_and_execute_contract(const p2p::proposal &cons_prop, std::string &new_lcl, hpfs::h32 &new_state)
    {
        if (ledger::save_ledger(cons_prop) == -1)
            return -1;

        new_lcl = ledger::ctx.get_lcl();
        const uint64_t new_lcl_seq_no = ledger::ctx.get_seq_no();

        LOG_INFO << "****Ledger created**** (lcl:" << new_lcl.substr(0, 15) << " state:" << cons_prop.state << ")";

        // After the current ledger seq no is updated, we remove any newly expired inputs from candidate set.
        {
            auto itr = ctx.candidate_user_inputs.begin();
            while (itr != ctx.candidate_user_inputs.end())
            {
                if (itr->second.maxledgerseqno <= new_lcl_seq_no)
                    ctx.candidate_user_inputs.erase(itr++);
                else
                    ++itr;
            }
        }

        // Send any output from the previous consensus round to locally connected users.
        dispatch_user_outputs(cons_prop, new_lcl_seq_no, new_lcl);

        // Execute the contract
        {
            sc::contract_execution_args &args = ctx.contract_ctx.args;
            args.time = cons_prop.time;
            args.lcl = new_lcl;

            // Populate user bufs.
            feed_user_inputs_to_contract_bufmap(args.userbufs, cons_prop);
            // TODO: Do something usefull with HP<-->SC channel.

            if (sc::execute_contract(ctx.contract_ctx) == -1)
            {
                LOG_ERROR << "Contract execution failed.";
                return -1;
            }

            state_common::ctx.set_state(args.post_execution_state_hash);
            new_state = args.post_execution_state_hash;

            extract_user_outputs_from_contract_bufmap(args.userbufs);

            sc::clear_args(args);
        }

        return 0;
    }

    /**
     * Dispatch any consensus-reached outputs to matching users if they are connected to us locally.
     * @param cons_prop The proposal that achieved consensus.
     */
    void dispatch_user_outputs(const p2p::proposal &cons_prop, const uint64_t lcl_seq_no, std::string_view lcl)
    {
        std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

        for (const std::string &hash : cons_prop.hash_outputs)
        {
            const auto cu_itr = ctx.candidate_user_outputs.find(hash);
            const bool hashfound = (cu_itr != ctx.candidate_user_outputs.end());
            if (!hashfound)
            {
                LOG_ERROR << "Output required but wasn't in our candidate outputs map, this will potentially cause desync.";
                // todo: consider fatal
            }
            else
            {
                // Send matching outputs to locally connected users.

                candidate_user_output &cand_output = cu_itr->second;

                const auto user_itr = usr::ctx.users.find(cand_output.userpubkey);
                if (user_itr != usr::ctx.users.end()) // match found
                {
                    const usr::connected_user &user = user_itr->second;
                    msg::usrmsg::usrmsg_parser parser(user.protocol);

                    std::string outputtosend;
                    outputtosend.swap(cand_output.output);

                    std::vector<uint8_t> msg;
                    parser.create_contract_output_container(msg, outputtosend, lcl_seq_no, lcl);

                    user.session.send(msg);
                }

                // now we can safely delete this candidate output.
                ctx.candidate_user_outputs.erase(cu_itr);
            }
        }
    }

    /**
     * Transfers consensus-reached inputs into the provided contract buf map so it can be fed into the contract process.
     * @param bufmap The contract bufmap which needs to be populated with inputs.
     * @param cons_prop The proposal that achieved consensus.
     */
    void feed_user_inputs_to_contract_bufmap(sc::contract_bufmap_t &bufmap, const p2p::proposal &cons_prop)
    {
        // Populate the buf map with all currently connected users regardless of whether they have inputs or not.
        // This is in case the contract wanted to emit some data to a user without needing any input.
        for (const std::string &pubkey : cons_prop.users)
            bufmap.try_emplace(pubkey, sc::contract_iobuf_pair());

        for (const std::string &hash : cons_prop.hash_inputs)
        {
            // For each consensus input hash, we need to find the actual input content to feed the contract.
            const auto itr = ctx.candidate_user_inputs.find(hash);
            const bool hashfound = (itr != ctx.candidate_user_inputs.end());
            if (!hashfound)
            {
                LOG_ERROR << "input required but wasn't in our candidate inputs map, this will potentially cause desync.";
                // TODO: consider fatal
            }
            else
            {
                // Populate the input content into the bufmap.

                candidate_user_input &cand_input = itr->second;

                std::string inputtofeed;
                inputtofeed.swap(cand_input.input);

                sc::contract_iobuf_pair &bufpair = bufmap[cand_input.userpubkey];
                bufpair.inputs.push_back(std::move(inputtofeed));

                // Remove the input from the candidate set because we no longer need it.
                //LOG_DEBUG << "candidate input deleted.";
                ctx.candidate_user_inputs.erase(itr);
            }
        }
    }

    /**
     * Reads any outputs the contract has produced on the provided buf map and transfers them to candidate outputs
     * for the next consensus round.
     * @param bufmap The contract bufmap containing the outputs produced by the contract.
     */
    void extract_user_outputs_from_contract_bufmap(sc::contract_bufmap_t &bufmap)
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

} // namespace consensus
