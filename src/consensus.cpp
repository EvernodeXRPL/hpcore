#include "pchheader.hpp"
#include "conf.hpp"
#include "util/rollover_hashset.hpp"
#include "usr/usr.hpp"
#include "usr/user_input.hpp"
#include "p2p/p2p.hpp"
#include "msg/fbuf/p2pmsg_conversion.hpp"
#include "msg/usrmsg_parser.hpp"
#include "msg/usrmsg_common.hpp"
#include "p2p/peer_session_handler.hpp"
#include "hplog.hpp"
#include "crypto.hpp"
#include "util/h32.hpp"
#include "util/sequence_hash.hpp"
#include "unl.hpp"
#include "ledger/ledger.hpp"
#include "ledger/ledger_query.hpp"
#include "consensus.hpp"
#include "sc/hpfs_log_sync.hpp"
#include "status.hpp"
#include "killswitch/killswitch.h"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace consensus
{
    constexpr float STAGE_THRESHOLDS[] = {0.5, 0.65, 0.8}; // Voting thresholds for stage 1,2,3
    constexpr float MAJORITY_THRESHOLD = 0.8;
    constexpr size_t ROUND_NONCE_SIZE = 64;
    constexpr const char *HPFS_SESSION_NAME = "ro_patch_file_to_hp";

    // Max no. of time to get unreliable votes before we try heuristics to increase vote receiving reliability.
    constexpr uint16_t MAX_UNRELIABLE_VOTES_ATTEMPTS = 5;

    consensus_context ctx;
    bool init_success = false;
    std::atomic<bool> is_patch_update_pending = false; // Keep track whether the patch file is changed by the SC and is not yet applied to runtime.

    int init()
    {
        refresh_time_config(false);

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
            if (kill_switch(util::get_epoch_milliseconds()))
            {
                LOG_ERROR << "Hot Pocket usage limit failure.";
                break;
            }

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
        revise_candidate_proposals(ctx.vote_status == VOTES_SYNCED);

        // Attempt to close the ledger after scanning last round stage 3 proposals.
        if (ctx.stage == 0)
            attempt_ledger_close();

        // Get current lcl, state, patch, primary shard and raw shard info.
        util::sequence_hash lcl_id = ledger::ctx.get_lcl_id();
        util::h32 state_hash = sc::contract_fs.get_parent_hash(sc::STATE_DIR_PATH);
        const util::h32 patch_hash = sc::contract_fs.get_parent_hash(sc::PATCH_FILE_PATH);
        const util::sequence_hash last_primary_shard_id = ledger::ctx.get_last_primary_shard_id();
        const util::sequence_hash last_raw_shard_id = ledger::ctx.get_last_raw_shard_id();

        if (ctx.stage == 0 || ctx.stage == 2)
        {
            // Broadcast non-unl proposal (NUP) containing inputs from locally connected users.
            // This is performed at stage 0 so we can to make sure this happens regardless of whether we are in-sync or not.
            // This is also performed at stage 2, so the next round receives the inputs before it starts.
            broadcast_nonunl_proposal();
        }

        if (ctx.stage == 0)
        {
            // Prepare the consensus candidate user inputs that we have accumulated so far. (We receive them periodically via NUPs)
            // The candidate inputs will be included in the stage 0 proposal.
            if (verify_and_populate_candidate_user_inputs(lcl_id.seq_no) == -1)
                return -1;

            const p2p::proposal p = create_stage0_proposal(state_hash, patch_hash, last_primary_shard_id, last_raw_shard_id);
            broadcast_proposal(p);

            ctx.stage = 1; // Transition to next stage.
        }
        else
        {
            // Stages 1,2,3

            const size_t unl_count = unl::count();
            vote_counter votes;

            // Check whether we are in sync with other nodes using proposals.
            {
                int new_sync_status = check_sync_status(unl_count, votes, lcl_id);

                if (ctx.vote_status != VOTES_SYNCED && new_sync_status == VOTES_UNRELIABLE)
                {
                    // If we are just becoming 'in-sync' after being out-of-sync, check the vote status again after the proper
                    // pruning of candidate proposals. This is because we relax the proposal pruning rules when we are not in sync,
                    // and we need to make the final vote status check after proper pruning rules are applied.

                    LOG_DEBUG << "Rechecking vote status after becoming in-sync.";
                    // Reset the voter for the new votes.
                    votes.reset();
                    revise_candidate_proposals(true);
                    new_sync_status = check_sync_status(unl_count, votes, lcl_id);
                }

                // Update the node's status if we went from in-sync to not-in-sync. We will report back as being in-sync only when ledger is created.
                if (ctx.vote_status == VOTES_SYNCED && new_sync_status != VOTES_SYNCED)
                    status::sync_status_changed(false);

                // This marks entering into a new sync cycle.
                if (new_sync_status == VOTES_DESYNC && !ctx.sync_ongoing)
                {
                    // Cleanup any unconsensed contract outputs we may have had before the sync cycle began because those are going to be
                    // irrelavant after the sync.
                    cleanup_output_collections();
                    ctx.sync_ongoing = true;
                }

                // If we just bacame in-sync after being in desync, we need to restore consensus context information from the synced ledger.
                if (ctx.vote_status != VOTES_SYNCED && new_sync_status == VOTES_SYNCED && ctx.sync_ongoing)
                    dispatch_synced_ledger_input_statuses(lcl_id);

                ctx.vote_status = new_sync_status;
            }

            if (ctx.vote_status == VOTES_UNRELIABLE)
            {
                ctx.unreliable_votes_attempts++;

                // If we get too many consecative unreliable vote rounds, then we perform time config sniffing just in case the unreliable votes
                // are caused because our roundtime config information is different from other nodes.
                if (ctx.unreliable_votes_attempts >= MAX_UNRELIABLE_VOTES_ATTEMPTS)
                {
                    refresh_time_config(true);
                    ctx.unreliable_votes_attempts = 0;
                }
            }
            else
            {
                ctx.unreliable_votes_attempts = 0;
            }

            if (ctx.vote_status == VOTES_SYNCED)
            {
                // If we are in sync, vote and broadcast the winning votes to next stage.
                const p2p::proposal p = create_stage123_proposal(votes, unl_count, state_hash, patch_hash, last_primary_shard_id, last_raw_shard_id);
                broadcast_proposal(p);

                // This marks the moment we finish a sync cycle. We are in stage 1 and we detect that our votes are in sync.
                if (ctx.stage == 1 && ctx.sync_ongoing)
                {
                    // Clear any sync recovery pending state if we enter stage 1 while being in sync.
                    ctx.sync_ongoing = false;
                    status::sync_status_changed(true);
                    LOG_DEBUG << "Sync recovery completed.";
                }
            }

            // We have finished a consensus stage.
            // Transition to next stage. (if at stage 3 go to next round stage 0)
            ctx.stage = (ctx.stage + 1) % 4;
        }

        return 0;
    }

    void attempt_ledger_close()
    {
        std::map<util::h32, uint32_t> hash_votes;
        util::h32 self_hash = util::h32_empty;
        util::h32 majority_hash = util::h32_empty;

        const auto itr = ctx.candidate_proposals.find(conf::cfg.node.public_key);
        if (itr == ctx.candidate_proposals.end() || itr->second.stage != 3)
        {
            LOG_DEBUG << "We haven't proposed to close any ledger.";
            return;
        }

        const p2p::proposal self_prop = itr->second;

        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            if (cp.stage == 3)
                increment(hash_votes, cp.root_hash);
        }

        uint32_t winning_votes = 0;
        for (const auto [hash, votes] : hash_votes)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_hash = hash;
            }
        }

        const uint32_t min_votes_required = ceil(MAJORITY_THRESHOLD * unl::count());
        if (winning_votes < min_votes_required)
        {
            LOG_INFO << "Cannot close ledger. Possible fork condition. won:" << winning_votes << " needed:" << min_votes_required;
            return;
        }

        if (self_prop.root_hash != majority_hash)
        {
            LOG_INFO << "Cannot close ledger. Our proposal:" << self_prop.root_hash << " does not match with majority:" << majority_hash;
            return;
        }

        LOG_DEBUG << "Closing ledger with proposal:" << self_prop.root_hash;

        // Upon successful ledger close condition, update the ledger and execute the contract using the consensus proposal.
        consensed_user_map consensed_users;
        if (prepare_consensed_users(consensed_users, self_prop) == -1 ||
            commit_consensus_results(self_prop, consensed_users) == -1)
        {
            LOG_ERROR << "Error occured when closing ledger";

            // Cleanup obsolete information before next round starts.
            cleanup_output_collections();
            cleanup_consensed_user_inputs(consensed_users);
        }
    }

    /**
     * Performs the consensus finalalization activities with the provided consensused information.
     * @param cons_prop The proposal which reached consensus.
     * @param consensed_users Set of consensed users and their consensed inputs and outputs.
     */
    int commit_consensus_results(const p2p::proposal &cons_prop, const consensus::consensed_user_map &consensed_users)
    {
        // Creating a ledger while sync ongoing happens when we discover that our ledger votes are in sync at stage 2 or 3. At this point,
        // we can create the ledger with majority votes. However we dont't have the raw contract outputs we should have had in the previous ledger
        // (because we were syncing the ledger and didn't execute the contract). So after this ledger creation we will most probably get a raw ledger
        // desync again because our raw outputs were different from other nodes. Therefore we don't consider this a proper/synced ledger creation until
        // we are fully out of the sync cycle. Hence we pass the sync_ongoing flag to indicate whether we are still inside a sync cycle or not.
        // Sync cycle is considered trully complete after the raw ledger is synced again and we discover in next round Stage 1 that our ledger votes
        // are in sync.

        // Persist the new ledger with the consensus results.
        if (ledger::update_ledger(cons_prop, consensed_users, ctx.sync_ongoing) == -1)
            return -1;

        util::sequence_hash lcl_id = ledger::ctx.get_lcl_id();

        if (!ctx.sync_ongoing)
            LOG_INFO << "****Ledger created**** (lcl:" << lcl_id << " state:" << cons_prop.state_hash << " patch:" << cons_prop.patch_hash << ")";

        // Now that there's a new ledger, prune any newly-expired candidate inputs.
        expire_candidate_inputs(lcl_id);

        // Inform locally connected users that their inputs made it into the ledger.
        dispatch_consensed_user_input_responses(consensed_users, lcl_id);

        // Send consensed outputs to locally connected users.
        dispatch_consensed_user_outputs(consensed_users, lcl_id);

        // Apply consensed config patch file changes to the hpcore runtime and hp.cfg.
        const util::h32 patch_hash = sc::contract_fs.get_parent_hash(sc::PATCH_FILE_PATH);
        if (apply_consensed_patch_file_changes(cons_prop.patch_hash, patch_hash) == -1)
            return -1;

        // Execute the smart contract with the consensed user inputs.
        if (execute_contract(cons_prop.time, consensed_users, lcl_id) == -1)
            return -1;

        return 0;
    }

    /**
     * Checks whether we are in sync with the received votes.
     * @return 0 if we are in sync. -1 on ledger or contract state desync. -2 if majority last ledger primary shard hash unreliable.
     */
    int check_sync_status(const size_t unl_count, vote_counter &votes, const util::sequence_hash &lcl_id)
    {
        bool is_last_primary_shard_desync = false;
        util::sequence_hash majority_primary_shard_id;
        if (check_last_primary_shard_hash_votes(is_last_primary_shard_desync, majority_primary_shard_id, votes, unl_count))
        {
            // We proceed further only if last primary shard hash check was success (meaning last primary shard hash check could be reliably performed).
            // Last primary shard hash sync is commenced if we are out-of-sync with majority last primary shard hash.
            if (is_last_primary_shard_desync)
            {
                // We first request the latest shard.
                const std::string majority_shard_seq_no_str = std::to_string(majority_primary_shard_id.seq_no);
                const std::string shard_path = std::string(ledger::PRIMARY_DIR).append("/").append(majority_shard_seq_no_str);
                ledger::ledger_sync_worker.is_last_primary_shard_syncing = true;
                ledger::ledger_sync_worker.set_target(true, shard_path, majority_primary_shard_id.hash, true);
            }

            // Check out raw shard hash with majority raw shard hash.
            bool is_last_raw_shard_desync = false;
            util::sequence_hash majority_raw_shard_id;
            check_last_raw_shard_hash_votes(is_last_raw_shard_desync, majority_raw_shard_id, votes);

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
                if (conf::cfg.node.history == conf::HISTORY::FULL)
                {
                    // If state or patch is desync set target for the hpfs log sync with the next lcl seq_no.
                    // When requesting the next seq_no, serving peer will give all the hpfs logs upto it's latest.
                    // So hash mismatch won't happen in the next round.
                    if (!ledger::ledger_sync_worker.is_last_primary_shard_syncing)
                        sc::hpfs_log_sync::set_sync_target(lcl_id.seq_no + 1, hpfs::get_root_hash(majority_patch_hash, majority_state_hash));
                }
                else
                {
                    // Patch file sync is prioritized, Therefore it is set in the front of the sync target list.
                    if (is_patch_desync)
                        sc::contract_sync_worker.set_target(false, sc::PATCH_FILE_PATH, majority_patch_hash, true);

                    if (is_state_desync)
                        sc::contract_sync_worker.set_target(true, sc::STATE_DIR_PATH, majority_state_hash);
                }
            }

            // If ledger raw shard is desync, We first request the latest raw shard.
            if (is_last_raw_shard_desync)
            {
                const std::string majority_shard_seq_no_str = std::to_string(majority_raw_shard_id.seq_no);
                const std::string shard_path = std::string(ledger::RAW_DIR).append("/").append(majority_shard_seq_no_str);
                ledger::ledger_sync_worker.is_last_raw_shard_syncing = true;
                ledger::ledger_sync_worker.set_target(true, shard_path, majority_raw_shard_id.hash);
            }

            // If shards aren't aligned with max shard count, do the relevant shard cleanups and requests.
            // In the first consensus round sync completion after the startup.
            if (!ledger::ledger_sync_worker.is_syncing && (!ledger::ctx.primary_shards_persisted || !ledger::ctx.raw_shards_persisted) && ledger::ledger_fs.acquire_rw_session() != -1)
            {
                if (!ledger::ctx.primary_shards_persisted)
                    ledger::persist_shard_history(majority_primary_shard_id.seq_no, ledger::PRIMARY_DIR);

                if (!ledger::ctx.raw_shards_persisted)
                    ledger::persist_shard_history(majority_raw_shard_id.seq_no, ledger::RAW_DIR);

                ledger::ledger_fs.release_rw_session();
            }

            // Proceed further only if last primary shard, last raw shard, state and patch hashes are in sync with majority.
            if (!is_last_primary_shard_desync && !is_last_raw_shard_desync && !is_state_desync && !is_patch_desync)
                return VOTES_SYNCED;

            // Last primary shard hash, last raw shard hash, patch or state desync.
            return VOTES_DESYNC;
        }

        // Majority last primary shard hash couldn't be detected reliably.
        return VOTES_UNRELIABLE;
    }

    /**
     * Moves proposals collected from the network into candidate proposals and
     * cleans up any outdated proposals from the candidate set.
     * @param in_sync Whether the node is currently on sync or not. We relax the pruning criteria if we are not in sync.
     */
    void revise_candidate_proposals(const bool in_sync)
    {
        // Move over the incoming proposal collection into a local list. This is to have a private working
        // set for candidate parsing and avoid threading conflicts with network incoming proposals.
        std::list<p2p::proposal> collected_proposals;
        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.collected_msgs.proposals_mutex);
            collected_proposals.splice(collected_proposals.end(), p2p::ctx.collected_msgs.proposals);
        }

        // Prune incoming proposals if they are older than existing proposal from same node.
        {
            auto itr = collected_proposals.begin();
            while (itr != collected_proposals.end())
            {
                const auto ex_itr = ctx.candidate_proposals.find(itr->pubkey);
                if (ex_itr != ctx.candidate_proposals.end()) // There is an existing proposal from same node.
                {
                    const p2p::proposal &existing = ex_itr->second;
                    if ((itr->time == existing.time && itr->stage < existing.stage) || // Existing proposal is from a newer stage in same round.
                        (itr->time < existing.time))                                   // Existing proposal is from an newer round
                    {
                        collected_proposals.erase(itr++); // Erase the incoming proposal as it is older.
                        continue;
                    }
                }

                ++itr;
            }
        }

        // Provide latest roundtime information to unl statistics.
        unl::update_time_config_stats(collected_proposals);

        // Move collected propsals to candidate set of proposals.
        for (const auto &p : collected_proposals)
        {
            ctx.candidate_proposals.erase(p.pubkey); // Erase if already exists.
            ctx.candidate_proposals.emplace(p.pubkey, std::move(p));
        }

        // Prune candidate proposals.
        {
            auto itr = ctx.candidate_proposals.begin();
            while (itr != ctx.candidate_proposals.end())
            {
                const p2p::proposal &cp = itr->second;

                // If we are in sync, only consider proposals which are from current or previous stage.
                // Otherwise consider all proposals as long as they are from the same round.
                const bool from_prev_round = ctx.round_start_time > cp.time && (ctx.round_start_time - cp.time) <= conf::cfg.contract.roundtime;
                const bool from_same_round = ctx.round_start_time == cp.time;
                const bool keep_candidate = in_sync ? (from_prev_round && ctx.stage == 0 && cp.stage == 3) ||
                                                          (from_same_round && ctx.stage >= cp.stage && (ctx.stage - cp.stage) <= 1)
                                                    : from_same_round;

                if (keep_candidate)
                {
                    LOG_DEBUG << "[s" << std::to_string(cp.stage)
                              << "-" << cp.root_hash
                              << "] u/i/t:" << cp.users.size()
                              << "/" << cp.input_ordered_hashes.size()
                              << "/" << cp.time
                              << " s:" << cp.state_hash
                              << " p:" << cp.patch_hash
                              << " ps:" << cp.last_primary_shard_id
                              << " rs:" << cp.last_raw_shard_id
                              << " [frm:" << (cp.from_self ? "self" : util::to_hex(cp.pubkey).substr(2, 8))
                              << "<" << (cp.recv_timestamp > cp.sent_timestamp ? (cp.recv_timestamp - cp.sent_timestamp) : 0) << "ms]";
                }
                else
                {
                    LOG_DEBUG << "Erased [s" << std::to_string(cp.stage)
                              << "-" << cp.root_hash
                              << "] [frm:" << (cp.from_self ? "self" : util::to_hex(cp.pubkey).substr(2, 8)) << "]";
                }

                if (keep_candidate)
                    ++itr;
                else
                    ctx.candidate_proposals.erase(itr++);
            }
        }
    }

    /**
     * Prepare the consensed user map including the consensed inputs/outputs for those users based on the consensus proposal.
     * @param consensed_users The consensed user map to populate.
     * @param cons_prop The proposal that reached consensus.
     * @return 0 on success. -1 on failure.
     */
    int prepare_consensed_users(consensed_user_map &consensed_users, const p2p::proposal &cons_prop)
    {
        int ret = 0;

        // Populate the users map with all consensed users regardless of whether they have inputs or not.
        for (const std::string &pubkey : cons_prop.users)
            consensed_users.try_emplace(pubkey, consensed_user{});

        // Prepare consensed user input set by joining consensus proposal input ordered hashes and candidate user input set.
        // consensed inputs are removed from the candidate set.
        for (const std::string &ordered_hash : cons_prop.input_ordered_hashes)
        {
            // For each consensus input ordered hash, we need to find the candidate input.
            const auto itr = ctx.candidate_user_inputs.find(ordered_hash);
            const bool hash_found = (itr != ctx.candidate_user_inputs.end());
            if (hash_found)
            {
                candidate_user_input &ci = itr->second;
                consensed_users[ci.user_pubkey].consensed_inputs.emplace_back(ordered_hash, ci.input);

                // Erase the consensed input from the candidate set.
                ctx.candidate_user_inputs.erase(itr);
            }
            else
            {
                LOG_WARNING << "Input required but wasn't in our candidate inputs map, this will potentially cause desync.";

                // We set error return value but keep on moving candidate inputs to consensed inputs.
                // This is so that their underlying buffers can get deallocated during stage 3 execution steps.
                ret = -1;
            }
        }

        // If final elected output hash matches our output hash, move the outputs into consensed outputs.
        // However, do not perform the safety matching check if we have just completed a sync cycle as we will not possess the outputs
        // generated during the previous ledger.
        {
            if (ctx.sync_ongoing || cons_prop.output_hash == ctx.user_outputs_hashtree.root_hash())
            {
                for (const auto &[hash, gen_output] : ctx.generated_user_outputs)
                {
                    consensed_user_output &con_out = consensed_users[gen_output.user_pubkey].consensed_outputs;
                    con_out.hash = hash;

                    for (const sc::contract_output &co : gen_output.outputs)
                        con_out.outputs.push_back(std::move(co.message));
                }
            }
            else
            {
                LOG_WARNING << "Consensus output hash didn't match our output hash.";
                ret = -1;
            }
        }

        return ret;
    }

    /**
     * Removes any candidate inputs that has lived past the current ledger seq no.
     */
    void expire_candidate_inputs(const util::sequence_hash &lcl_id)
    {
        std::unordered_map<std::string, std::vector<usr::input_status_response>> rejections;

        auto itr = ctx.candidate_user_inputs.begin();
        while (itr != ctx.candidate_user_inputs.end())
        {
            if (itr->second.max_ledger_seq_no <= lcl_id.seq_no)
            {
                const std::string input_hash = std::string(util::get_string_suffix(itr->first, BLAKE3_OUT_LEN));
                rejections[itr->second.user_pubkey].push_back(usr::input_status_response{input_hash, msg::usrmsg::REASON_MAX_LEDGER_EXPIRED});

                // Erase the candidate input along with its data buffer in the input store.
                usr::input_store.purge(itr->second.input);
                ctx.candidate_user_inputs.erase(itr++);
            }
            else
            {
                ++itr;
            }
        }

        // Inform any connected users about their expired inputs.
        usr::send_input_status_responses(rejections);
    }

    /**
     * Cleans up any consensused user inputs that are not relevant for the next round.
     * @param consensed_users The consensed user map that contains consensed inputs.
     * @return 0 on success. -1 on failure.
     */
    int cleanup_consensed_user_inputs(const consensed_user_map &consensed_users)
    {
        int ret = 0;

        // Purges the underyling buffers that belong to provided consensed user inputs.
        for (const auto &[pubkey, user] : consensed_users)
        {
            for (const consensed_user_input &ci : user.consensed_inputs)
            {
                if (usr::input_store.purge(ci.input) == -1)
                    ret = -1;
            }
        }

        return ret;
    }

    /**
     * Clears the contract output collections that are no longer needed for the next round.
     */
    void cleanup_output_collections()
    {
        ctx.user_outputs_our_sig.clear();
        ctx.generated_user_outputs.clear();
        ctx.user_outputs_hashtree.clear();
        ctx.user_outputs_unl_sig.clear();
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

        // Rounds are discreet windows of roundtime.

        if (ctx.stage == 0)
        {
            // This gets the start time of current round window. Stage 0 must start in the window after that.
            const uint64_t previous_round_start = (((uint64_t)((now - ctx.round_boundry_offset) / conf::cfg.contract.roundtime)) * conf::cfg.contract.roundtime) + ctx.round_boundry_offset;

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
            const uint64_t stage_start = ctx.round_start_time + conf::cfg.contract.roundtime - ((4 - ctx.stage) * ctx.stage_time);

            // Compute stage time wait.
            // Node wait between stages to collect enough proposals from previous stages from other nodes.
            const uint64_t to_wait = stage_start - now;

            // If a node doesn't have enough time (eg. due to network delay) to recieve/send reliable stage proposals for next stage,
            // it will join in next round. Otherwise it will continue particapating in this round.
            if (stage_start < now || to_wait < ctx.stage_reset_wait_threshold) //todo: self claculating/adjusting network delay
            {
                LOG_DEBUG << "Missed stage " << std::to_string(ctx.stage) << " window. Resetting to stage 0.";
                ctx.stage = 0;
                return false;
            }
            else
            {
                LOG_DEBUG << "Waiting " << to_wait << "ms for stage " << std::to_string(ctx.stage);
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
                std::list<usr::submitted_user_input> user_inputs;
                user_inputs.splice(user_inputs.end(), user.submitted_inputs);
                user.collected_input_size = 0; // Reset the collected inputs size counter.

                // We should create an entry for each user pubkey, even if the user has no inputs. This is
                // because this data map will be used to track connected users as well in addition to inputs.
                nup.user_inputs.try_emplace(user.pubkey, std::move(user_inputs));
            }
        }

        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_nonunl_proposal(fbuf, nup);
        p2p::broadcast_message(fbuf, true, false, false, 1); // Use high priority send.

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

        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_proposal(fbuf, p);
        p2p::broadcast_message(fbuf, true, false, !conf::cfg.contract.is_consensus_public, 1); // Use high priority send.

        LOG_DEBUG << "Proposed-s" << std::to_string(p.stage)
                  << " u/i/t:" << p.users.size()
                  << "/" << p.input_ordered_hashes.size()
                  << "/" << p.time
                  << " s:" << p.state_hash
                  << " p:" << p.patch_hash
                  << " ps:" << p.last_primary_shard_id
                  << " rs:" << p.last_raw_shard_id;
    }

    /**
     * Enqueue npl messages to the npl messages queue.
     * @param npl_msg Constructed npl message.
     * @return Returns true if enqueue is success otherwise false.
     */
    bool push_npl_message(const p2p::npl_message &npl_msg)
    {
        std::scoped_lock lock(ctx.contract_ctx_mutex);
        if (ctx.contract_ctx)
            return ctx.contract_ctx->args.npl_messages.try_enqueue(std::move(npl_msg));
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
        // Maintains users and any input-rejected responses we should send to them.
        // Key: user pubkey. Value: List of responses for that user.
        std::unordered_map<std::string, std::vector<usr::input_status_response>> rejections;

        // Maintains merged list of users with each user's inputs grouped under the user.
        // Key: user pubkey, Value: List of inputs from the user.
        std::unordered_map<std::string, std::list<usr::submitted_user_input>> input_groups;

        // Move over NUPs collected from the network input groups (grouped by user).
        {
            std::list<p2p::nonunl_proposal> collected_nups;
            {
                std::scoped_lock lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);
                collected_nups.splice(collected_nups.end(), p2p::ctx.collected_msgs.nonunl_proposals);
            }

            for (p2p::nonunl_proposal &p : collected_nups)
            {
                for (auto &[pubkey, sbmitted_inputs] : p.user_inputs)
                {
                    // Move any user inputs from each NUP over to the grouped inputs under the user pubkey.
                    std::list<usr::submitted_user_input> &input_list = input_groups[pubkey];
                    input_list.splice(input_list.end(), sbmitted_inputs);
                }
            }
        }

        for (auto &[pubkey, submitted_inputs] : input_groups)
        {
            // Populate user list with this user's pubkey.
            ctx.candidate_users.emplace(pubkey);

            std::list<usr::extracted_user_input> extracted_inputs;

            for (const usr::submitted_user_input &submitted_input : submitted_inputs)
            {
                usr::extracted_user_input extracted = {};
                const char *reject_reason = usr::extract_submitted_input(pubkey, submitted_input, extracted);

                if (reject_reason == NULL)
                    extracted_inputs.push_back(std::move(extracted));
                else
                    rejections[pubkey].push_back(usr::input_status_response{crypto::get_hash(submitted_input.sig), reject_reason});
            }

            // This will sort the inputs in nonce order so the validation will follow the same order on all nodes.
            extracted_inputs.sort();

            // Keep track of total input length to verify against remaining balance.
            // We only process inputs in the submitted order that can be satisfied with the remaining account balance.
            size_t total_input_size = 0;

            for (const usr::extracted_user_input &extracted_input : extracted_inputs)
            {
                util::buffer_view stored_input; // Contains pointer to the input data stored in memfd accessed by the contract.
                std::string ordered_hash;

                // Validate the input against all submission criteria.
                const char *reject_reason = usr::validate_user_input_submission(pubkey, extracted_input, lcl_seq_no, total_input_size, ordered_hash, stored_input);

                if (reject_reason == NULL && !stored_input.is_null())
                {
                    // No reject reason means we should go ahead and subject the input to consensus.
                    ctx.candidate_user_inputs.try_emplace(
                        ordered_hash,
                        candidate_user_input(pubkey, stored_input, extracted_input.max_ledger_seq_no));
                }

                // If the input was rejected we need to inform the user.
                if (reject_reason != NULL)
                {
                    // We need to consider the last 32 bytes of each ordered hash to get input hash without the nonce prefix.
                    const std::string input_hash = std::string(util::get_string_suffix(ordered_hash, BLAKE3_OUT_LEN));
                    rejections[pubkey].push_back(usr::input_status_response{std::move(input_hash), reject_reason});
                }
            }
        }

        input_groups.clear();

        usr::send_input_status_responses(rejections);

        return 0;
    }

    p2p::proposal create_stage0_proposal(const util::h32 &state_hash, const util::h32 &patch_hash,
                                         const util::sequence_hash &last_primary_shard_id, const util::sequence_hash &last_raw_shard_id)
    {
        // This is the proposal that stage 0 votes on.
        // We report our own values in stage 0.
        p2p::proposal p;
        p.time = ctx.round_start_time;
        p.stage = 0;
        p.state_hash = state_hash;
        p.patch_hash = patch_hash;
        p.last_primary_shard_id = last_primary_shard_id;
        p.last_raw_shard_id = last_raw_shard_id;
        p.time_config = CURRENT_TIME_CONFIG;
        crypto::random_bytes(p.nonce, ROUND_NONCE_SIZE);

        // Populate the proposal with set of candidate user pubkeys.
        p.users.swap(ctx.candidate_users);

        // Populate the proposal with hashes of user inputs.
        for (const auto &[hash, cand_input] : ctx.candidate_user_inputs)
            p.input_ordered_hashes.emplace(hash);

        // Populate the output hash and our signature. This is the merkle tree root hash of user outputs and state hash.
        p.output_hash = ctx.user_outputs_hashtree.root_hash();
        p.output_sig = ctx.user_outputs_our_sig;

        return p;
    }

    p2p::proposal create_stage123_proposal(vote_counter &votes, const size_t unl_count, const util::h32 &state_hash, const util::h32 &patch_hash,
                                           const util::sequence_hash &last_primary_shard_id, const util::sequence_hash &last_raw_shard_id)
    {
        // The proposal to be emited at the end of this stage.
        p2p::proposal p;
        p.stage = ctx.stage;
        // We always vote for our current information regardless of what other peers are saying.
        // If there's a fork condition we will either request shards or hpfs state from
        // our peers or we will halt depending on level of consensus on the sides of the fork.
        p.state_hash = state_hash;
        p.patch_hash = patch_hash;
        p.last_primary_shard_id = last_primary_shard_id;
        p.last_raw_shard_id = last_raw_shard_id;
        p.time_config = CURRENT_TIME_CONFIG;
        p.output_hash.resize(BLAKE3_OUT_LEN); // Default empty hash.

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
            for (const std::string &ordered_hash : cp.input_ordered_hashes)
                if (ctx.candidate_user_inputs.count(ordered_hash) > 0)
                    increment(votes.inputs, ordered_hash);

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
                p.input_ordered_hashes.emplace(hash);

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

        // time is voted on majority basis.
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
     * Check whether our last primary shard hash is consistent with the proposals being made by our UNL peers last primary shard hash votes.
     * @param is_desync Indicates whether our ledger primary hash is out-of-sync with majority ledger primary hash. Only valid if this method returns True.
     * @param majority_primary_shard_id Majority primary shard id.
     * @param votes Vote counter for this stage.
     * @param unl_count Number of unl peers.
     * @return True if majority ledger primary hash could be calculated reliably. False if shard index hash check failed due to unreliable votes.
     */
    bool check_last_primary_shard_hash_votes(bool &is_desync, util::sequence_hash &majority_primary_shard_id, vote_counter &votes, const size_t unl_count)
    {
        uint32_t total_ledger_primary_hash_votes = 0;

        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.last_ledger_primary_shard, cp.last_primary_shard_id);
            total_ledger_primary_hash_votes++;
        }

        // Check whether we have received enough votes in total.
        const uint32_t min_votes_required = ceil(MAJORITY_THRESHOLD * unl_count);
        if (total_ledger_primary_hash_votes < min_votes_required)
        {
            LOG_INFO << "Not enough peers proposing to perform consensus. votes:" << total_ledger_primary_hash_votes << " needed:" << min_votes_required;
            return false;
        }

        uint32_t winning_votes = 0;
        for (const auto [shard_id, votes] : votes.last_ledger_primary_shard)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_primary_shard_id = shard_id;
            }
        }

        if (winning_votes < min_votes_required)
        {
            LOG_INFO << "No consensus on last shard hash. Possible fork condition. won:" << winning_votes << " needed:" << min_votes_required;
            return false;
        }
        else if (ledger::ctx.get_last_primary_shard_id() != majority_primary_shard_id)
        {
            LOG_INFO << "We are not on the consensus ledger, we must request history from a peer.";
            is_desync = true;
            return true;
        }
        else
        {
            // Reaching here means we have reliable amount of winning last shard hash votes and our last shard hash matches with majority last shard hash.
            is_desync = false;
            return true;
        }
    }

    /**
     * Check whether our last raw shard hash is consistent with the proposals being made by our UNL peers last raw shard hash votes.
     * @param is_ledger_blob_desync Indicates whether our ledger raw hash is out-of-sync with majority ledger raw hash.
     * @param majority_primary_shard_id Majority primary shard id.
     * @param votes Vote counter for this stage.
     */
    void check_last_raw_shard_hash_votes(bool &is_ledger_blob_desync, util::sequence_hash &majority_raw_shard_id, vote_counter &votes)
    {
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.last_ledger_raw_shard, cp.last_raw_shard_id);
        }

        uint32_t winning_votes = 0;
        for (const auto [shard_id, votes] : votes.last_ledger_raw_shard)
        {
            if (votes > winning_votes)
            {
                winning_votes = votes;
                majority_raw_shard_id = shard_id;
            }
        }

        is_ledger_blob_desync = (conf::cfg.node.history_config.max_raw_shards > 0 && ledger::ctx.get_last_raw_shard_id() != majority_raw_shard_id);
    }

    /**
     * Check state hash against the winning and canonical state hash.
     * @param is_state_desync Flag to determine whether contract state is out of sync.
     * @param majority_state_hash consensed state hash.
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

        is_state_desync = (sc::contract_fs.get_parent_hash(sc::STATE_DIR_PATH) != majority_state_hash);
    }

    /**
     * Check state hash against the winning and canonical state hash.
     * @param is_patch_desync Flag to determine whether patch file is out of sync.
     * @param majority_patch_hash consensed patch hash.
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

        is_patch_desync = (sc::contract_fs.get_parent_hash(sc::PATCH_FILE_PATH) != majority_patch_hash);
    }

    /**
     * Executes the contract after consensus.
     * @param time The consensus time.
     * @param consensed_users Consensed users and their inputs.
     * @param lcl_id Current lcl id of the node.
     */
    int execute_contract(const uint64_t time, const consensed_user_map &consensed_users, const util::sequence_hash &lcl_id)
    {
        if (!conf::cfg.contract.execute || ctx.is_shutting_down)
            return 0;

        {
            std::scoped_lock lock(ctx.contract_ctx_mutex);
            ctx.contract_ctx.emplace(usr::input_store);
        }

        sc::contract_execution_args &args = ctx.contract_ctx->args;
        args.readonly = false;
        args.time = time;

        // lcl to be passed to the contract.
        args.lcl_id = lcl_id;

        // Populate contract user bufs.
        feed_user_inputs_to_contract_bufmap(args.userbufs, consensed_users);

        if (sc::execute_contract(ctx.contract_ctx.value()) == -1)
        {
            LOG_ERROR << "Consensus contract execution failed.";
            return -1;
        }

        // Cleanup the fed inputs and extract the generated outputs.
        cleanup_consensed_user_inputs(consensed_users);
        extract_user_outputs_from_contract_bufmap(args.userbufs);

        // Get the new state hash after contract execution.
        const util::h32 &new_state_hash = args.post_execution_state_hash;

        // Update state hash in contract fs global hash tracker.
        sc::contract_fs.set_parent_hash(sc::STATE_DIR_PATH, new_state_hash);

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

        return 0;
    }

    /**
     * Dispatch acceptence status responses to consensed user inputs, if the recipients are connected to us locally.
     * @param consensed_users The map of consensed users containing their inputs.
     * @param lcl_id The ledger the inputs got included in.
     */
    void dispatch_consensed_user_input_responses(const consensed_user_map &consensed_users, const util::sequence_hash &lcl_id)
    {
        if (consensed_users.empty())
            return;

        std::unordered_map<std::string, std::vector<usr::input_status_response>> responses;

        for (const auto &[pubkey, user] : consensed_users)
        {
            if (user.consensed_inputs.empty())
                continue;

            const auto [itr, success] = responses.emplace(pubkey, std::vector<usr::input_status_response>());

            for (const consensed_user_input &ci : user.consensed_inputs)
            {
                // We need to consider the last 32 bytes of each ordered hash to get input hash without the nonce prefix.
                const std::string input_hash = std::string(util::get_string_suffix(ci.ordered_hash, BLAKE3_OUT_LEN));
                itr->second.push_back(usr::input_status_response{input_hash, NULL});
            }
        }

        usr::send_input_status_responses(responses, lcl_id.seq_no, lcl_id.hash);
    }

    /**
     * Dispatch any consensus-reached outputs to matching users if they are connected to us locally.
     * @param consensed_users The map of consensed users containing their outputs.
     * @param lcl_id The ledger the outputs got included in.
     */
    void dispatch_consensed_user_outputs(const consensed_user_map &consensed_users, const util::sequence_hash &lcl_id)
    {
        if (!consensed_users.empty())
        {
            std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

            for (const auto &[pubkey, cu] : consensed_users)
            {
                if (cu.consensed_outputs.outputs.empty())
                    continue;

                // Find user to send by pubkey.
                const auto user_itr = usr::ctx.users.find(pubkey);
                if (user_itr != usr::ctx.users.end()) // match found
                {
                    const usr::connected_user &user = user_itr->second;
                    msg::usrmsg::usrmsg_parser parser(user.protocol);

                    // Get the collapsed hash tree with this user's output hash remaining independently.
                    util::merkle_hash_node collapsed_hash_root = ctx.user_outputs_hashtree.collapse(cu.consensed_outputs.hash);

                    // Send the outputs and signatures to the user.
                    std::vector<uint8_t> msg;
                    parser.create_contract_output_container(msg, cu.consensed_outputs.hash, cu.consensed_outputs.outputs, collapsed_hash_root, ctx.user_outputs_unl_sig,
                                                            lcl_id.seq_no, lcl_id.hash.to_string_view());
                    user.session.send(msg);
                }
            }
        }

        cleanup_output_collections();
    }

    /**
     * Dispatches any input responses corresponsing to candidate inputs that we have been holding during while syncing.
     */
    void dispatch_synced_ledger_input_statuses(const util::sequence_hash &lcl_id)
    {
        // Find out any inputs we were holding that may have made their way into the ledger while we were syncing,
        // and reply with 'accepted' input statuses if the user is conencted to us.
        std::unordered_map<std::string, std::vector<usr::input_status_response>> responses;
        auto itr = ctx.candidate_user_inputs.begin();
        while (itr != ctx.candidate_user_inputs.end())
        {
            std::string_view ordered_hash = itr->first;
            const std::string input_hash = std::string(util::get_string_suffix(ordered_hash, BLAKE3_OUT_LEN));
            std::optional<ledger::ledger_user_input> input;
            std::optional<ledger::ledger_record> ledger;
            if (ledger::query::get_input_by_hash(lcl_id.seq_no, input_hash, input, ledger) != -1 && input)
            {
                // Each 'accepted' status response must be associated with the ledger seqno/hash that contained the input.
                responses[itr->second.user_pubkey].push_back(usr::input_status_response{
                    input_hash, NULL, input->ledger_seq_no, *(util::h32 *)ledger->ledger_hash.data()});

                // Erase the candidate input since we no longer need to hold it.
                ctx.candidate_user_inputs.erase(itr++);
            }
            else
            {
                ++itr;
            }
        }

        usr::send_input_status_responses(responses);
    }

    /**
     * Transfers consensus-reached inputs into the provided contract buf map so it can be fed into the contract process.
     * @param bufmap The contract bufmap which needs to be populated with inputs.
     * @param consensed_users Set of consensed users keyed by user binary pubkey.
     */
    void feed_user_inputs_to_contract_bufmap(sc::contract_bufmap_t &bufmap, const consensed_user_map &consensed_users)
    {
        for (const auto &[pubkey, user] : consensed_users)
        {
            // Populate the buf map with user pubkey regardless of whether user has any inputs or not.
            // This is in case the contract wanted to emit some data to a user without needing any input.
            const auto [itr, success] = bufmap.emplace(pubkey, sc::contract_iobufs());

            // Populate the input contents into the bufmap.
            // It's VERY important that we preserve the original input order when feeding to the contract as well.
            for (const consensed_user_input &ci : user.consensed_inputs)
                itr->second.inputs.push_back(ci.input);
        }
    }

    /**
     * Reads any outputs the contract has produced on the provided buf map and transfers them to generated outputs
     * for the next consensus round.
     * @param bufmap The contract bufmap containing the outputs produced by the contract.
     */
    void extract_user_outputs_from_contract_bufmap(sc::contract_bufmap_t &bufmap)
    {
        for (const auto &[pubkey, bufs] : bufmap)
        {
            // For each user calculate the total hash of their outputs.
            // Final hash for user = hash(pubkey + outputs...)

            if (!bufs.outputs.empty())
            {
                // Generate hash of all sorted outputs combined with user pubkey.
                std::vector<std::string_view> to_hash;
                to_hash.push_back(pubkey);
                for (const sc::contract_output &con_out : bufs.outputs)
                    to_hash.push_back(con_out.message);

                ctx.generated_user_outputs.try_emplace(
                    crypto::get_list_hash(to_hash),
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
        // Check whether is there any patch changes to be applied which reached consensus.
        if (is_patch_update_pending && current_patch_hash == prop_patch_hash)
        {
            if (sc::contract_fs.start_ro_session(HPFS_SESSION_NAME, false) != -1)
            {
                // Appling new patch file changes to hpcore runtime.
                if (conf::apply_patch_config(HPFS_SESSION_NAME) == -1)
                {
                    LOG_ERROR << "Applying patch file changes after consensus failed.";
                    sc::contract_fs.stop_ro_session(HPFS_SESSION_NAME);
                    return -1;
                }
                else
                {
                    unl::update_unl_changes_from_patch();
                    // Refresh values in consensus context to match newly synced roundtime from patch file.
                    refresh_time_config(false);
                    is_patch_update_pending = false;
                }
            }

            if (sc::contract_fs.stop_ro_session(HPFS_SESSION_NAME) == -1)
                return -1;
        }
        return 0;
    }

    /**
     * Updates roundtime-based calculations with the latest time config value.
     * @param perform_detection Whether or not to detect time config from latest network information.
     */
    void refresh_time_config(const bool perform_detection)
    {
        if (perform_detection)
        {
            LOG_DEBUG << "Detecting time config...";
            const uint32_t majority_time_config = unl::get_majority_time_config();

            if (majority_time_config == 0 || CURRENT_TIME_CONFIG == majority_time_config)
                return;

            LOG_INFO << "New time config detected:" << majority_time_config << " previous:" << CURRENT_TIME_CONFIG;

            // Time config is a single value derived from roundtime*100 + stage_slice. Here we derive back the original components.
            conf::cfg.contract.roundtime = (majority_time_config / 100);
            conf::cfg.contract.stage_slice = majority_time_config - (conf::cfg.contract.roundtime * 100);
        }

        // We allocate configured stage slice for stages 1, 2, 3. Stage 0 gets the entire remaining time from the round window.
        ctx.stage_time = conf::cfg.contract.roundtime * conf::cfg.contract.stage_slice / 100;
        ctx.stage_reset_wait_threshold = conf::cfg.contract.roundtime / 10;

        // We use a time window boundry offset based on contract id to vary the window boundries between
        // different contracts with same round time.
        std::hash<std::string> str_hasher;
        ctx.round_boundry_offset = str_hasher(conf::cfg.contract.id) % conf::cfg.contract.roundtime;
    }

} // namespace consensus
