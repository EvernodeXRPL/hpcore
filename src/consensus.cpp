#include "pchheader.hpp"
#include "conf.hpp"
#include "util/rollover_hashset.hpp"
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
#include "util/h32.hpp"
#include "hpfs/hpfs.hpp"
#include "hpfs/hpfs_sync.hpp"
#include "unl.hpp"
#include "ledger.hpp"
#include "consensus.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace consensus
{
    constexpr float STAGE_THRESHOLDS[] = {0.5, 0.65, 0.8}; // Voting thresholds for stage 1,2,3
    constexpr float MAJORITY_THRESHOLD = 0.8;
    constexpr size_t ROUND_NONCE_SIZE = 64;
    constexpr const char *HPFS_SESSION_NAME = "ro_patch_file_to_hp";

    consensus_context ctx;
    bool init_success = false;
    std::atomic<bool> is_patch_update_pending = false; // Keep track whether the patch file is changed by the SC and is not yet applied to runtime.

    int init()
    {
        // We allocate 1/4 of roundtime for each stage (0, 1, 2, 3).
        ctx.stage_time = conf::cfg.contract.roundtime / 4;
        ctx.stage_reset_wait_threshold = conf::cfg.contract.roundtime / 10;

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
            {
                std::scoped_lock lock(ctx.contract_ctx_mutex);
                if (ctx.contract_ctx)
                    sc::stop(ctx.contract_ctx.value());
            }

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
        // A consensus round consists of 4 stages (0,1,2,3).
        // For a given stage, this function may get visited multiple times due to time-wait conditions.

        if (!wait_and_proceed_stage())
            return 0; // This means the stage has been reset.

        LOG_DEBUG << "Started stage " << std::to_string(ctx.stage);

        // Throughout consensus, we continously update and prune the candidate proposals for newly
        // arived ones and expired ones.
        revise_candidate_proposals();

        // If possible, switch back to validator mode before stage processing. (if we were syncing before)
        check_sync_completion();

        // Get current lcl and state.
        std::string lcl = ledger::ctx.get_lcl();
        const uint64_t lcl_seq_no = ledger::ctx.get_seq_no();
        hpfs::hpfs_mount &contract_fs = hpfs::contract_fs; // Ref of the contract_fs object.
        util::h32 state_hash = contract_fs.get_parent_hash(hpfs::STATE_DIR_PATH);
        util::h32 patch_hash = contract_fs.get_parent_hash(hpfs::PATCH_FILE_PATH);

        if (ctx.stage == 0)
        {
            // Prepare the consensus candidate user inputs that we have accumulated so far. (We receive them periodically via NUPs)
            // The candidate inputs will be included in the stage 0 proposal.
            if (verify_and_populate_candidate_user_inputs(lcl_seq_no) == -1)
                return -1;

            const p2p::proposal p = create_stage0_proposal(lcl, state_hash, patch_hash);
            broadcast_proposal(p);

            ctx.stage = 1; // Transition to next stage.
        }
        else
        {
            // Stages 1,2,3

            const size_t unl_count = unl::count();
            vote_counter votes;
            const int sync_status = check_sync_status(lcl, unl_count, votes);

            if (sync_status == 0)
            {
                // If we are in sync, vote and broadcast the winning votes to next stage.
                const p2p::proposal p = create_stage123_proposal(votes, lcl, unl_count, state_hash, patch_hash);
                broadcast_proposal(p);

                // Upon successful consensus at stage 3, update the ledger and execute the contract using the consensus proposal.
                if (ctx.stage == 3 && update_ledger_and_execute_contract(p, lcl, state_hash, patch_hash) == -1)
                    LOG_ERROR << "Error occured in Stage 3 consensus execution.";
            }

            if (ctx.stage == 2)
            {
                // At end of stage 2, broadcast non-unl proposal (NUP) containing inputs from locally connected users.
                // This will be captured and verified during every round stage 0.
                // (We broadcast this at stage 2 in order to give it enough time to reach others before next round stage 0)
                broadcast_nonunl_proposal();
            }

            // We have finished a consensus stage. Transition or reset stage based on sync status.

            if (sync_status == -2)
                ctx.stage = 0; // Majority lcl unreliable. Reset to stage 0.
            else
                ctx.stage = (ctx.stage + 1) % 4; // Transition to next stage. (if at stage 3 go to next round stage 0)
        }

        return 0;
    }

    /**
     * Checks whether we are in sync with the received votes.
     * @return 0 if we are in sync. -1 on lcl or hpfs desync. -2 if majority lcl unreliable.
     */
    int check_sync_status(std::string_view lcl, const size_t unl_count, vote_counter &votes)
    {
        // Check if we're ahead/behind of consensus lcl.
        bool is_lcl_desync = false;
        std::string majority_lcl;
        if (check_lcl_votes(is_lcl_desync, majority_lcl, votes, lcl, unl_count))
        {
            // We proceed further only if lcl check was success (meaning lcl check could be reliably performed).

            // State lcl sync if we are out-of-sync with majority lcl.
            if (is_lcl_desync)
            {
                conf::change_role(conf::ROLE::OBSERVER);
                ledger::set_sync_target(majority_lcl);
            }

            // Check our state with majority state.
            bool is_state_desync = false;
            bool is_patch_desync = false;
            util::h32 majority_state_hash = util::h32_empty;
            util::h32 majority_patch_hash = util::h32_empty;
            check_patch_votes(is_patch_desync, majority_patch_hash, votes);
            check_state_votes(is_state_desync, majority_state_hash, votes);

            // Stop any patch file updates triggered from the sc. The sync is triggered because the changes
            // done by the contract is not meeting consensus.
            if (is_patch_desync)
                is_patch_update_pending = false;

            // Start hpfs sync if we are out-of-sync with majority hpfs patch hash or state hash.
            if (is_state_desync || is_patch_desync)
            {
                conf::change_role(conf::ROLE::OBSERVER);

                // This queue holds all the sync targets which needs to get synced in contract fs.
                std::queue<hpfs::sync_target> sync_target_list;
                if (is_patch_desync)
                    sync_target_list.push(hpfs::sync_target{"patch", majority_patch_hash, hpfs::PATCH_FILE_PATH, hpfs::BACKLOG_ITEM_TYPE::FILE});

                if (is_state_desync)
                    sync_target_list.push(hpfs::sync_target{"state", majority_state_hash, hpfs::STATE_DIR_PATH, hpfs::BACKLOG_ITEM_TYPE::DIR});

                // Set sync targets for contract fs.
                hpfs::contract_sync_worker.set_target(std::move(sync_target_list));
            }

            // Proceed further only if both lcl and state are in sync with majority.
            if (!is_lcl_desync && !is_state_desync && !is_patch_desync)
            {
                conf::change_role(conf::ROLE::VALIDATOR);
                return 0;
            }

            // lcl or hpfs desync.
            return -1;
        }

        // Majority lcl couldn't be detected reliably.
        return -2;
    }

    /**
     * Checks whether we can switch back from currently ongoing observer-mode sync operation
     * that has been completed.
     */
    void check_sync_completion()
    {
        if (conf::cfg.node.role == conf::ROLE::OBSERVER && !hpfs::contract_sync_worker.ctx.is_syncing && !ledger::sync_ctx.is_syncing)
            conf::change_role(conf::ROLE::VALIDATOR);
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
            ctx.candidate_proposals.erase(proposal.pubkey); // Erase if already exists.
            ctx.candidate_proposals.emplace(proposal.pubkey, std::move(proposal));
        }

        // Prune any outdated proposals.
        auto itr = ctx.candidate_proposals.begin();
        const uint64_t time_now = util::get_epoch_milliseconds();
        while (itr != ctx.candidate_proposals.end())
        {
            const p2p::proposal &cp = itr->second;
            const uint64_t time_diff = (time_now > cp.sent_timestamp) ? (time_now - cp.sent_timestamp) : 0;
            const int8_t stage_diff = ctx.stage - cp.stage;

            // only consider recent proposals and proposals from previous stage and current stage.
            const bool keep_candidate = (time_diff < (conf::cfg.contract.roundtime * 4)) && (stage_diff == -3 || stage_diff <= 1);
            LOG_DEBUG << (keep_candidate ? "Prop--->" : "Erased")
                      << " [s" << std::to_string(cp.stage)
                      << "] u/i:" << cp.users.size()
                      << "/" << cp.input_hashes.size()
                      << " ts:" << std::to_string(cp.time)
                      << " lcl:" << cp.lcl.substr(0, 15)
                      << " state:" << cp.state_hash
                      << " patch:" << cp.patch_hash
                      << " [from:" << ((cp.pubkey == conf::cfg.node.public_key) ? "self" : util::to_hex(cp.pubkey).substr(2, 10)) << "]"
                      << "(" << std::to_string(cp.recv_timestamp > cp.sent_timestamp ? cp.recv_timestamp - cp.sent_timestamp : 0) << "ms)";

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
    bool wait_and_proceed_stage()
    {
        // Here, nodes try to synchronise nodes stages using network clock.
        // We devide universal time to windows of equal size of roundtime. Each round must be synced with the
        // start of a window.

        const uint64_t now = util::get_epoch_milliseconds();

        // Rrounds are discreet windows of roundtime.

        if (ctx.stage == 0)
        {
            // This gets the start time of current round window. Stage 0 must start in the window after that.
            const uint64_t previous_round_start = (((uint64_t)(now / conf::cfg.contract.roundtime)) * conf::cfg.contract.roundtime);

            // Stage 0 must start in the next round window.
            // (This makes sure stage 3 gets whichever the remaining time in the round after stages 0,1,2)
            ctx.round_start_time = previous_round_start + conf::cfg.contract.roundtime;
            const uint64_t to_wait = ctx.round_start_time - now;

            LOG_DEBUG << "Waiting " << to_wait << "ms for next round stage 0.";
            util::sleep(to_wait);
            return true;
        }
        else
        {
            const uint64_t stage_start = ctx.round_start_time + (ctx.stage * ctx.stage_time);

            // Compute stage time wait.
            // Node wait between stages to collect enough proposals from previous stages from other nodes.
            const uint64_t to_wait = stage_start - now;

            // If a node doesn't have enough time (eg. due to network delay) to recieve/send reliable stage proposals for next stage,
            // it will join in next round. Otherwise it will continue particapating in this round.
            if (to_wait < ctx.stage_reset_wait_threshold) //todo: self claculating/adjusting network delay
            {
                LOG_DEBUG << "Missed stage " << std::to_string(ctx.stage) << " window. Resetting to stage 0.";
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
     * Broadcasts the given proposal to all connected peers if in VALIDATOR mode. Does not send in OBSERVER mode.
     * @return 0 on success. -1 if no peers to broadcast.
     */
    void broadcast_proposal(const p2p::proposal &p)
    {
        // In observer mode, we do not send out proposals.
        if (conf::cfg.node.role == conf::ROLE::OBSERVER || !conf::cfg.node.is_unl) // If we are a non-unl node, do not broadcast proposals.
            return;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_proposal(fbuf, p);
        p2p::broadcast_message(fbuf, true, false, !conf::cfg.contract.is_consensus_public);

        LOG_DEBUG << "Proposed <s" << std::to_string(p.stage) << "> u/i:" << p.users.size()
                  << "/" << p.input_hashes.size()
                  << " ts:" << std::to_string(p.time)
                  << " lcl:" << p.lcl.substr(0, 15)
                  << " state:" << p.state_hash
                  << " patch:" << p.patch_hash;
    }

    /**
     * Enqueue npl messages to the npl messages queue.
     * @param npl_msg Constructed npl message.
     * @return Returns true if enqueue is success otherwise false.
     */
    bool push_npl_message(p2p::npl_message &npl_msg)
    {
        std::scoped_lock lock(ctx.contract_ctx_mutex);
        if (ctx.contract_ctx)
            return ctx.contract_ctx->args.npl_messages.try_enqueue(npl_msg);
        return false;
    }

    /**
     * Enqueue conrol messages to the control messages queue.
     * @param control_msg Constructed control message.
     * @return Returns true if enqueue is success otherwise false.
     */
    bool push_control_message(const std::string &control_msg)
    {
        std::scoped_lock lock(ctx.contract_ctx_mutex);
        if (ctx.contract_ctx)
            return ctx.contract_ctx->args.control_messages.try_enqueue(control_msg);
        return false;
    }

    /**
     * Verifies the user signatures and populate non-expired user inputs from collected
     * non-unl proposals (if any) into consensus candidate data.
     */
    int verify_and_populate_candidate_user_inputs(const uint64_t lcl_seq_no)
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

            for (const usr::user_input &umsg : umsgs)
            {
                const char *reject_reason = NULL;

                if (appbill_balance_exceeded)
                {
                    reject_reason = msg::usrmsg::REASON_APPBILL_BALANCE_EXCEEDED;
                }
                else
                {
                    util::buffer_view input;
                    std::string hash;
                    uint64_t max_lcl_seqno;
                    reject_reason = usr::validate_user_input_submission(pubkey, umsg, lcl_seq_no, total_input_len, hash, input, max_lcl_seqno);

                    if (reject_reason == NULL && !input.is_null())
                    {
                        // No reject reason means we should go ahead and subject the input to consensus.
                        ctx.candidate_user_inputs.try_emplace(
                            hash,
                            candidate_user_input(pubkey, input, max_lcl_seqno));
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
                        const char *reject_reason = std::get<2>(resp);

                        // We are not sending any status response for 'already submitted' inputs. This is because the user
                        // would have gotten the proper status response during first submission.
                        if (reject_reason != msg::usrmsg::REASON_ALREADY_SUBMITTED)
                        {
                            msg::usrmsg::usrmsg_parser parser(std::get<0>(resp));
                            const std::string &msg_sig = std::get<1>(resp);
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

        return 0;
    }

    p2p::proposal create_stage0_proposal(std::string_view lcl, util::h32 state_hash, util::h32 patch_hash)
    {
        // This is the proposal that stage 0 votes on.
        // We report our own values in stage 0.
        p2p::proposal p;
        p.time = ctx.round_start_time;
        p.stage = 0;
        p.lcl = lcl;
        p.state_hash = state_hash;
        p.patch_hash = patch_hash;
        crypto::random_bytes(p.nonce, ROUND_NONCE_SIZE);

        // Populate the proposal with set of candidate user pubkeys.
        p.users.swap(ctx.candidate_users);

        // Populate the proposal with hashes of user inputs.
        for (const auto &[hash, cand_input] : ctx.candidate_user_inputs)
            p.input_hashes.emplace(hash);

        // Populate the output hash and our signature. This is the merkle tree root hash of user outputs and state hash.
        p.output_hash = ctx.user_outputs_hashtree.root_hash();
        p.output_sig = ctx.user_outputs_our_sig;

        return p;
    }

    p2p::proposal create_stage123_proposal(vote_counter &votes, std::string_view lcl, const size_t unl_count, const util::h32 state_hash, const util::h32 patch_hash)
    {
        // The proposal to be emited at the end of this stage.
        p2p::proposal p;
        p.stage = ctx.stage;
        p.state_hash = state_hash;
        p.patch_hash = patch_hash;

        // We always vote for our current lcl and state regardless of what other peers are saying.
        // If there's a fork condition we will either request history and hpfs state from
        // our peers or we will halt depending on level of consensus on the sides of the fork.
        p.lcl = lcl;

        const uint64_t time_now = util::get_epoch_milliseconds();

        // Vote for rest of the proposal fields by looking at candidate proposals.
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            // Vote for times.
            // Everyone votes on the discreet time, as long as it's not in the future and within 2 round times.
            if (time_now > cp.time && (time_now - cp.time) <= (conf::cfg.contract.roundtime * 2))
                increment(votes.time, cp.time);

            // Vote for round nonce.
            increment(votes.nonce, cp.nonce);

            // Vote for user pubkeys.
            for (const std::string &pubkey : cp.users)
                increment(votes.users, pubkey);

            // Vote for user inputs (hashes). Only vote for the inputs that are in our candidate_inputs set.
            for (const std::string &hash : cp.input_hashes)
                if (ctx.candidate_user_inputs.count(hash) > 0)
                    increment(votes.inputs, hash);

            // Vote for contract output hash.
            increment(votes.output_hash, cp.output_hash);
        }

        uint32_t required_votes = ceil(STAGE_THRESHOLDS[ctx.stage - 1] * unl_count);

        // todo: check if inputs being proposed by another node are actually spoofed inputs
        // from a user locally connected to this node.

        // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

        // Add user pubkeys which have votes over stage threshold to proposal.
        for (const auto &[pubkey, numvotes] : votes.users)
            if (numvotes >= required_votes || (ctx.stage == 1 && numvotes > 0))
                p.users.emplace(pubkey);

        // Add inputs which have votes over stage threshold to proposal.
        for (const auto &[hash, numvotes] : votes.inputs)
            if (numvotes >= required_votes || (ctx.stage == 1 && numvotes > 0))
                p.input_hashes.emplace(hash);

        // Reset required votes for majority votes.
        required_votes = ceil(MAJORITY_THRESHOLD * unl_count);

        // Add the output hash which has most votes over stage threshold to proposal.
        uint32_t highest_output_vote = 0;
        for (const auto &[hash, numvotes] : votes.output_hash)
        {
            if (numvotes >= required_votes && numvotes > highest_output_vote)
            {
                highest_output_vote = numvotes;
                p.output_hash = hash;
            }
        }

        if (!p.output_hash.empty())
        {
            if (ctx.stage < 3)
            {
                // If the elected hash is our output hash, then place our output signature in the proposal.
                // We only do this if we are at stage 1 or 2.
                if (p.output_hash == ctx.user_outputs_hashtree.root_hash())
                    p.output_sig = ctx.user_outputs_our_sig;
            }
            else
            {
                // If this is the stage 3 proposal, collect the UNL output signatures matching the elected output hash.
                for (const auto &[pubkey, cp] : ctx.candidate_proposals)
                {
                    if (cp.output_hash == p.output_hash)
                        ctx.user_outputs_unl_sig.emplace_back(cp.pubkey, cp.output_sig);
                }
            }
        }

        // time is voted on a simple sorted (highest to lowest) and majority basis.
        uint32_t highest_time_vote = 0;
        for (const auto &[time, numvotes] : votes.time)
        {
            if (numvotes > highest_time_vote)
            {
                highest_time_vote = numvotes;
                p.time = time;
            }
        }
        // If final time happens to be 0 (this can happen if there were no proposals to vote for), we set the time manually.
        if (p.time == 0)
            p.time = ctx.round_start_time;

        // Round nonce is voted on a simple sorted (highest to lowest) and majority basis, since there will always be disagreement.
        uint32_t highest_nonce_vote = 0;
        for (const auto [nonce, numvotes] : votes.nonce)
        {
            if (numvotes > highest_nonce_vote)
            {
                highest_nonce_vote = numvotes;
                p.nonce = nonce;
            }
        }

        return p;
    }

    /**
     * Check whether our lcl is consistent with the proposals being made by our UNL peers lcl votes.
     * @param is_desync Indicates whether our lcl is out-of-sync with majority lcl. Only valid if this method returns True.
     * @param majority_lcl The majority lcl based on the votes received. Only valid if this method returns True.
     * @param votes Vote counter for this stage.
     * @param lcl Our lcl.
     * @return True if majority lcl could be calculated reliably. False if lcl check failed due to unreliable votes.
     */
    bool check_lcl_votes(bool &is_desync, std::string &majority_lcl, vote_counter &votes, std::string_view lcl, const size_t unl_count)
    {
        uint32_t total_lcl_votes = 0;

        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.lcl, cp.lcl);
            total_lcl_votes++;
        }

        // Check whether we have received enough votes in total.
        const uint32_t min_required = ceil(MAJORITY_THRESHOLD * unl_count);
        if (total_lcl_votes < min_required)
        {
            LOG_INFO << "Not enough peers proposing to perform consensus. votes:" << total_lcl_votes << " needed:" << min_required;
            return false;
        }

        uint32_t winning_votes = 0;
        for (const auto [lcl, votes] : votes.lcl)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_lcl = lcl;
            }
        }

        // If winning lcl is not matched with our lcl, that means we are not on the consensus ledger.
        // If that's the case we should request history straight away.
        if (lcl != majority_lcl)
        {
            LOG_DEBUG << "We are not on the consensus ledger, we must request history from a peer.";
            is_desync = true;
            return true;
        }
        else
        {
            // Check wheher there are enough winning votes for the lcl to be reliable.
            const uint32_t min_wins_required = ceil(MAJORITY_THRESHOLD * ctx.candidate_proposals.size());
            if (winning_votes < min_wins_required)
            {
                LOG_INFO << "No consensus on lcl. Possible fork condition. won:" << winning_votes << " needed:" << min_wins_required;
                return false;
            }
            else
            {
                // Reaching here means we have reliable amount of winning lcl votes and our lcl matches with majority lcl.
                is_desync = false;
                return true;
            }
        }
    }

    /**
     * Check state hash against the winning and canonical state hash.
     * @param is_state_desync Flag to determine whether contract state is out of sync.
     * @param majority_state_hash Consensused state hash.
     * @param votes The voting table.
     */
    void check_state_votes(bool &is_state_desync, util::h32 &majority_state_hash, vote_counter &votes)
    {
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.state_hash, cp.state_hash);
        }

        uint32_t winning_votes = 0;
        for (const auto [state_hash, votes] : votes.state_hash)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_state_hash = state_hash;
            }
        }

        is_state_desync = (hpfs::contract_fs.get_parent_hash(hpfs::STATE_DIR_PATH) != majority_state_hash);
    }

    /**
     * Check state hash against the winning and canonical state hash.
     * @param is_patch_desync Flag to determine whether patch file is out of sync.
     * @param majority_patch_hash Consensused patch hash.
     * @param votes The voting table.
     */
    void check_patch_votes(bool &is_patch_desync, util::h32 &majority_patch_hash, vote_counter &votes)
    {
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.patch_hash, cp.patch_hash);
        }

        uint32_t winning_votes = 0;
        for (const auto [patch_hash, votes] : votes.patch_hash)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_patch_hash = patch_hash;
            }
        }

        is_patch_desync = (hpfs::contract_fs.get_parent_hash(hpfs::PATCH_FILE_PATH) != majority_patch_hash);
    }

    /**
     * Update the ledger and execute the contract after consensus.
     * @param cons_prop The proposal that reached consensus.
     * @param new_state_hash The state hash.
     * @param patch_hash The patch hash.
     */
    int update_ledger_and_execute_contract(const p2p::proposal &cons_prop, std::string &new_lcl, util::h32 &new_state_hash, const util::h32 &patch_hash)
    {
        // Map to temporarily store the raw inputs along with the hash.
        std::unordered_map<std::string, usr::raw_user_input> raw_inputs;

        // Add raw_inputs to the proposal if full history mode is on.
        if (conf::cfg.node.full_history)
        {
            for (const auto &hash : cons_prop.input_hashes)
            {
                const auto itr = ctx.candidate_user_inputs.find(hash);
                if (itr != ctx.candidate_user_inputs.end())
                {
                    // Add raw_input to the map along with the input hash.
                    candidate_user_input &cand_input = itr->second;
                    // Taking the raw input string from the buffer_view.
                    std::string input;
                    if (usr::input_store.read_buf(cand_input.input, input) != -1)
                    {
                        usr::raw_user_input raw_input(cand_input.userpubkey, std::move(input));
                        raw_inputs.emplace(hash, std::move(raw_input));
                    }
                }
            }
        }

        if (ledger::save_ledger(cons_prop, std::move(raw_inputs)) == -1)
            return -1;

        new_lcl = ledger::ctx.get_lcl();
        const uint64_t new_lcl_seq_no = ledger::ctx.get_seq_no();

        LOG_INFO << "****Ledger created**** (lcl:" << new_lcl.substr(0, 15) << " state:" << cons_prop.state_hash << " patch:" << cons_prop.patch_hash << ")";

        // Apply consensed patch file changes to the hpcore runtime and hp.cfg.
        if (apply_consensed_patch_file_changes(cons_prop.patch_hash, patch_hash) == -1)
            return -1;

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
        if (dispatch_user_outputs(cons_prop, new_lcl_seq_no, new_lcl) == -1)
            return -1;

        // Execute the contract
        if (conf::cfg.contract.execute && !ctx.is_shutting_down)
        {
            {
                std::scoped_lock lock(ctx.contract_ctx_mutex);
                ctx.contract_ctx.emplace(usr::input_store);
            }

            sc::contract_execution_args &args = ctx.contract_ctx->args;
            args.readonly = false;
            args.time = cons_prop.time;
            args.lcl = new_lcl;

            // Populate user bufs.
            if (feed_user_inputs_to_contract_bufmap(args.userbufs, cons_prop) == -1)
                return -1;

            if (sc::execute_contract(ctx.contract_ctx.value()) == -1)
            {
                LOG_ERROR << "Contract execution failed.";
                return -1;
            }

            // Update state hash in contract fs global hash tracker.
            hpfs::contract_fs.set_parent_hash(hpfs::STATE_DIR_PATH, args.post_execution_state_hash);
            new_state_hash = args.post_execution_state_hash;

            extract_user_outputs_from_contract_bufmap(args.userbufs);

            // Generate user output hash merkle tree and signature with state hash included.
            if (!ctx.generated_user_outputs.empty())
            {
                std::vector<std::string_view> hashes;
                for (const auto &[hash, output] : ctx.generated_user_outputs)
                    hashes.push_back(hash);
                hashes.push_back(new_state_hash.to_string_view());
                ctx.user_outputs_hashtree.populate(hashes);
                ctx.user_outputs_our_sig = crypto::sign(ctx.user_outputs_hashtree.root_hash(), conf::cfg.node.private_key);
            }

            {
                std::scoped_lock lock(ctx.contract_ctx_mutex);
                ctx.contract_ctx.reset();
            }
        }

        return 0;
    }

    /**
     * Dispatch any consensus-reached outputs to matching users if they are connected to us locally.
     * @param cons_prop The proposal that achieved consensus.
     */
    int dispatch_user_outputs(const p2p::proposal &cons_prop, const uint64_t lcl_seq_no, std::string_view lcl)
    {
        if (cons_prop.output_hash == ctx.user_outputs_hashtree.root_hash())
        {
            std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

            // If final elected output hash matches our output hash, distribute the outputs
            // to locally connected users.
            for (auto &[hash, user_output] : ctx.generated_user_outputs)
            {
                // Find user to send by pubkey.
                const auto user_itr = usr::ctx.users.find(user_output.userpubkey);
                if (user_itr != usr::ctx.users.end()) // match found
                {
                    const usr::connected_user &user = user_itr->second;
                    msg::usrmsg::usrmsg_parser parser(user.protocol);

                    // Send the outputs and signatures to the user.
                    std::vector<uint8_t> msg;

                    // Get the collapsed hash tree with this user's output hash remaining independently.
                    util::merkle_hash_node collapsed_hash_root = ctx.user_outputs_hashtree.collapse(hash);

                    std::vector<std::string_view> outputs;
                    for (const sc::contract_output &output : user_output.outputs)
                        outputs.emplace_back(output.message);

                    parser.create_contract_output_container(msg, outputs, collapsed_hash_root, ctx.user_outputs_unl_sig, lcl_seq_no, lcl);

                    user.session.send(msg);
                }

                user_output.outputs.clear(); // We no longer need this user's outputs.
            }
        }
        else
        {
            LOG_INFO << "Output required but didn't match our output hash.";
        }

        // Clear the output hash tree and signature because we no longer need it.
        ctx.user_outputs_hashtree.clear();
        ctx.user_outputs_our_sig.clear();
        ctx.user_outputs_unl_sig.clear();
        ctx.generated_user_outputs.clear();

        return 0;
    }

    /**
     * Transfers consensus-reached inputs into the provided contract buf map so it can be fed into the contract process.
     * @param bufmap The contract bufmap which needs to be populated with inputs.
     * @param cons_prop The proposal that achieved consensus.
     */
    int feed_user_inputs_to_contract_bufmap(sc::contract_bufmap_t &bufmap, const p2p::proposal &cons_prop)
    {
        // Populate the buf map with all currently connected users regardless of whether they have inputs or not.
        // This is in case the contract wanted to emit some data to a user without needing any input.
        for (const std::string &pubkey : cons_prop.users)
        {
            bufmap.try_emplace(pubkey, sc::contract_iobufs());
        }

        for (const std::string &hash : cons_prop.input_hashes)
        {
            // For each consensus input hash, we need to find the actual input content to feed the contract.
            const auto itr = ctx.candidate_user_inputs.find(hash);
            const bool hashfound = (itr != ctx.candidate_user_inputs.end());
            if (!hashfound)
            {
                LOG_ERROR << "Input required but wasn't in our candidate inputs map, this will potentially cause desync.";
                return -1;
            }
            else
            {
                // Populate the input content into the bufmap.
                // It's VERY important that we preserve the proposal input hash order when feeding to the contract as well.
                candidate_user_input &cand_input = itr->second;
                sc::contract_iobufs &contract_user = bufmap[cand_input.userpubkey];
                contract_user.inputs.push_back(cand_input.input);

                // Remove the input from the candidate set because we no longer need it.
                ctx.candidate_user_inputs.erase(itr);
            }
        }

        return 0;
    }

    /**
     * Reads any outputs the contract has produced on the provided buf map and transfers them to generated outputs
     * for the next consensus round.
     * @param bufmap The contract bufmap containing the outputs produced by the contract.
     */
    void extract_user_outputs_from_contract_bufmap(sc::contract_bufmap_t &bufmap)
    {
        for (auto &[pubkey, bufs] : bufmap)
        {
            if (!bufs.outputs.empty())
            {
                std::vector<std::string_view> vect;
                // Adding public key.
                vect.push_back(pubkey);
                // Only using message to generate hash for output messages. Length is not needed.
                for (sc::contract_output &output : bufs.outputs)
                {
                    vect.push_back(output.message);
                }

                const std::string hash = crypto::get_hash(vect);
                ctx.generated_user_outputs.try_emplace(
                    std::move(hash),
                    generated_user_output(pubkey, std::move(bufs.outputs)));
            }
        }
        bufmap.clear();
    }

    /**
     * Increment voting table counter.
     * @param counter The counter map in which a vote should be incremented.
     * @param candidate The candidate whose vote should be increased by 1.
     */
    template <typename T>
    void increment(std::map<T, uint32_t> &counter, const T &candidate)
    {
        if (counter.count(candidate))
            counter[candidate]++;
        else
            counter.try_emplace(candidate, 1);
    }

    /**
     * Apply patch file changes after verification from consensus.
     * @param prop_patch_hash Hash of patch file which reached consensus.
     * @param current_patch_hash Hash of the current patch file.
     * @return 0 on success. -1 on failure.
    */
    int apply_consensed_patch_file_changes(const util::h32 &prop_patch_hash, const util::h32 &current_patch_hash)
    {
        hpfs::hpfs_mount &contract_fs = hpfs::contract_fs;

        // Check whether is there any patch changes to be applied which reached consensus.
        if (is_patch_update_pending && current_patch_hash == prop_patch_hash)
        {
            if (contract_fs.start_ro_session(HPFS_SESSION_NAME, false) != -1)
            {
                // Appling new patch file changes to hpcore runtime.
                if (conf::apply_patch_config(HPFS_SESSION_NAME) == -1)
                {
                    LOG_ERROR << "Appling patch file changes after consensus failed.";
                    contract_fs.stop_ro_session(HPFS_SESSION_NAME);
                    return -1;
                }
                else
                {
                    unl::update_unl_changes_from_patch();
                    is_patch_update_pending = false;
                }
            }

            if (contract_fs.stop_ro_session(HPFS_SESSION_NAME) == -1)
                return -1;
        }
        return 0;
    }

} // namespace consensus
