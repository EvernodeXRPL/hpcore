#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../usr/user_input.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/common_helpers.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "../hplog.hpp"
#include "../crypto.hpp"
#include "../sc.hpp"
#include "../hpfs/h32.hpp"
#include "../hpfs/hpfs.hpp"
#include "../state/state_sync.hpp"
#include "ledger_handler.hpp"
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
    constexpr float MAJORITY_THRESHOLD = 0.8;

    consensus_context ctx;

    bool init_success = false;

    int init()
    {
        //set start stage
        ctx.stage = 0;

        //load lcl details from lcl history.
        ledger_history ldr_hist = load_ledger();
        ctx.led_seq_no = ldr_hist.led_seq_no;
        ctx.lcl = ldr_hist.lcl;
        ctx.ledger_cache.swap(ldr_hist.cache);

        if (hpfs::get_root_hash(ctx.state) == -1)
            return -1;

        LOG_INFO << "Initial state: " << ctx.state;

        // We allocate 1/5 of the round time to each stage expect stage 3. For stage 3 we allocate 2/5.
        // Stage 3 is allocated an extra stage_time unit becayse a node needs enough time to
        // catch up from lcl/state desync.
        ctx.stage_time = conf::cfg.roundtime / 5;
        ctx.stage_reset_wait_threshold = conf::cfg.roundtime / 10;

        init_success = true;
        return 0;
    }

    /**
 * Cleanup any resources.
 */
    void deinit()
    {
    }

    int run_consensus()
    {
        while (true)
        {
            if (consensus() == -1)
                return -1;
        }

        return 0;
    }

    int consensus()
    {
        // A consensus round consists of 4 stages (0,1,2,3).
        // For a given stage, this function may get visited multiple times due to time-wait conditions.

        uint64_t stage_start = 0;
        if (!wait_and_proceed_stage(stage_start))
            return 0; // This means the stage has been reset.

        // Get the latest current time.
        ctx.time_now = stage_start;
        std::list<p2p::proposal> collected_proposals;

        // Throughout consensus, we move over the incoming proposals collected via the network so far into
        // the candidate proposal set (move and append). This is to have a private working set for the consensus
        // and avoid threading conflicts with network incoming proposals.
        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.proposals_mutex);
            collected_proposals.splice(collected_proposals.end(), p2p::ctx.collected_msgs.proposals);
        }

        //Copy collected propsals to candidate set of proposals.
        //Add propsals of new nodes and replace proposals from old nodes to reflect current status of nodes.
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
        // Throughout consensus, we move over the incoming npl messages collected via the network so far into
        // the candidate npl message set (move and append). This is to have a private working set for the consensus
        // and avoid threading conflicts with network incoming npl messages.
        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.npl_messages_mutex);
            for (const auto &npl : p2p::ctx.collected_msgs.npl_messages)
            {
                const fbschema::p2pmsg::Container *container = fbschema::p2pmsg::GetContainer(npl.data());
                // Only the npl messages with a valid lcl will be passed down to the contract. lcl should match the previous round's lcl
                if (fbschema::flatbuff_bytes_to_sv(container->lcl()) != ctx.lcl)
                    continue;

                ctx.candidate_npl_messages.push_back(std::move(npl));
            }
            p2p::ctx.collected_msgs.npl_messages.clear();
        }

        LOG_DBG << "Started stage " << std::to_string(ctx.stage);

        if (ctx.stage == 0) // Stage 0 means begining of a consensus round.
        {
            // Broadcast non-unl proposals (NUP) containing inputs from locally connected users.
            broadcast_nonunl_proposal();
            //util::sleep(conf::cfg.roundtime / 10);

            // Verify and transfer user inputs from incoming NUPs onto consensus candidate data.
            verify_and_populate_candidate_user_inputs();

            // In stage 0 we create a novel proposal and broadcast it.
            const p2p::proposal stg_prop = create_stage0_proposal();
            broadcast_proposal(stg_prop);
        }
        else // Stage 1, 2, 3
        {
            purify_candidate_proposals();

            // Initialize vote counters
            vote_counter votes;

            // check if we're ahead/behind of consensus lcl
            bool is_lcl_desync = false, should_request_history = false;
            std::string majority_lcl;
            check_lcl_votes(is_lcl_desync, should_request_history, majority_lcl, votes);

            if (is_lcl_desync)
            {
                if (should_request_history)
                {
                    LOG_INFO << "Syncing lcl. Curr lcl:" << cons::ctx.lcl.substr(0, 15) << " majority:" << majority_lcl.substr(0, 15);

                    // TODO: If we are in a lcl fork condition try to rollback state with the help of
                    // state_restore to rollback state checkpoints before requesting new state.

                    // Handle minority going forward when boostrapping cluster.
                    // Here we are mimicking invalid min ledger scenario.
                    if (majority_lcl == GENESIS_LEDGER)
                    {
                        ctx.last_requested_lcl = majority_lcl;
                        p2p::history_response res;
                        res.error = p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER;
                        handle_ledger_history_response(std::move(res));
                    }
                    else
                    {
                        //create history request message and request history from a random peer.
                        send_ledger_history_request(ctx.lcl, majority_lcl);
                    }
                }
            }
            else
            {
                bool is_state_desync = false;
                hpfs::h32 majority_state = hpfs::h32_empty;
                check_state_votes(is_state_desync, majority_state, votes);

                if (is_state_desync)
                {
                    conf::change_operating_mode(conf::OPERATING_MODE::OBSERVER);
                    state_sync::sync_state(majority_state);
                }
                else
                {
                    conf::change_operating_mode(conf::OPERATING_MODE::PROPOSER);

                    // In stage 1, 2, 3 we vote for incoming proposals and promote winning votes based on thresholds.
                    const p2p::proposal stg_prop = create_stage123_proposal(votes);

                    broadcast_proposal(stg_prop);

                    if (ctx.stage == 3)
                    {
                        if (apply_ledger(stg_prop) == -1)
                            return -1;

                        // node has finished a consensus round (all 4 stages).
                        LOG_INFO << "****Stage 3 consensus reached**** (lcl:" << ctx.lcl.substr(0, 15)
                                 << " state:" << ctx.state << ")";
                    }
                }
            }
        }

        // Node has finished a consensus stage. Transition to next stage.
        ctx.stage = (ctx.stage + 1) % 4;
        return 0;
    }

    /**
 * Cleanup any outdated proposals from the candidate set.
 */
    void purify_candidate_proposals()
    {
        auto itr = ctx.candidate_proposals.begin();
        while (itr != ctx.candidate_proposals.end())
        {
            const p2p::proposal &cp = itr->second;

            // only consider recent proposals and proposals from previous stage and current stage.
            if ((ctx.time_now - cp.timestamp < conf::cfg.roundtime * 4) && cp.stage >= (ctx.stage - 1))
            {
                ++itr;

                bool self = cp.pubkey == conf::cfg.pubkey;
                LOG_DBG << "Proposal [stage" << std::to_string(cp.stage)
                        << "] users:" << cp.users.size()
                        << " hinp:" << cp.hash_inputs.size()
                        << " hout:" << cp.hash_outputs.size()
                        << " ts:" << std::to_string(cp.time)
                        << " lcl:" << cp.lcl.substr(0, 15)
                        << " state:" << cp.state
                        << " self:" << self;
            }
            else
            {
                ctx.candidate_proposals.erase(itr++);
            }
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

        // Rrounds are divided into windows of roundtime.
        // This gets the start time of current round window. Stage 0 must start in the next window.
        const uint64_t current_round_start = (((uint64_t)(now / conf::cfg.roundtime)) * conf::cfg.roundtime);

        if (ctx.stage == 0)
        {
            // Stage 0 must start in the next round window.
            stage_start = current_round_start + conf::cfg.roundtime;
            const int64_t to_wait = stage_start - now;

            LOG_DBG << "Waiting " << std::to_string(to_wait) << "ms for next round stage 0";
            util::sleep(to_wait);
            return true;
        }
        else
        {
            stage_start = current_round_start + (ctx.stage * ctx.stage_time);

            // Compute stage time wait.
            // Node wait between stages to collect enough proposals from previous stages from other nodes.
            const int64_t to_wait = stage_start - now;

            // If a node doesn't have enough time (eg. due to network delay) to recieve/send reliable stage proposals for next stage,
            // it will continue particapating in this round, otherwise will join in next round.
            if (to_wait < ctx.stage_reset_wait_threshold) //todo: self claculating/adjusting network delay
            {
                LOG_DBG << "Missed stage " << std::to_string(ctx.stage) << " window. Resetting to stage 0";
                ctx.stage = 0;
                return false;
            }
            else
            {
                LOG_DBG << "Waiting " << std::to_string(to_wait) << "ms for stage " << std::to_string(ctx.stage);
                util::sleep(to_wait);
                return true;
            }
        }
    }

    /**
 * Broadcasts any inputs from locally connected users via an NUP.
 * @return 0 for successful broadcast. -1 for failure.
 */
    void broadcast_nonunl_proposal()
    {
        std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);

        if (usr::ctx.users.empty())
            return;

        // Construct NUP.
        p2p::nonunl_proposal nup;

        for (auto &[sid, user] : usr::ctx.users)
        {
            std::list<usr::user_submitted_message> usermsgs;
            usermsgs.splice(usermsgs.end(), user.submitted_inputs);

            // We should create an entry for each user pubkey, even if the user has no inputs. This is
            // because this data map will be used to track connected users as well in addition to inputs.
            nup.user_messages.try_emplace(user.pubkey, std::move(usermsgs));
        }

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_nonunl_proposal(fbuf, nup);
        p2p::broadcast_message(fbuf, true);

        LOG_DBG << "NUP sent."
                << " users:" << nup.user_messages.size();
    }

    /**
 * Verifies the user signatures and populate non-expired user inputs from collected
 * non-unl proposals (if any) into consensus candidate data.
 */
    void verify_and_populate_candidate_user_inputs()
    {
        // Lock the user sessions.
        std::lock_guard<std::mutex> users_lock(usr::ctx.users_mutex);

        // Lock the list so any network activity is blocked.
        std::lock_guard<std::mutex> nups_lock(p2p::ctx.collected_msgs.nonunl_proposals_mutex);
        for (const p2p::nonunl_proposal &p : p2p::ctx.collected_msgs.nonunl_proposals)
        {
            for (const auto &[pubkey, umsgs] : p.user_messages)
            {
                // Locate this user's socket session in case we need to send any status messages regarding user inputs.
                const comm::comm_session *session = usr::get_session_by_pubkey(pubkey);

                // Populate user list with this user's pubkey.
                ctx.candidate_users.emplace(pubkey);

                // Keep track of total input length to verify against remaining balance.
                // We only process inputs in the submitted order that can be satisfied with the remaining account balance.
                size_t total_input_len = 0;
                bool appbill_balance_exceeded = false;

                for (const usr::user_submitted_message &umsg : umsgs)
                {
                    const char *reject_reason = NULL;
                    const std::string sig_hash = crypto::get_hash(umsg.sig);

                    // Check for duplicate messages using hash of the signature.
                    if (ctx.recent_userinput_hashes.try_emplace(sig_hash))
                    {
                        // Verify the signature of the message content.
                        if (crypto::verify(umsg.content, umsg.sig, pubkey) == 0)
                        {
                            std::string nonce;
                            std::string input;
                            uint64_t maxledgerseqno;
                            jusrmsg::extract_input_container(nonce, input, maxledgerseqno, umsg.content);

                            // Ignore the input if our ledger has passed the input TTL.
                            if (maxledgerseqno > ctx.led_seq_no)
                            {
                                if (!appbill_balance_exceeded)
                                {
                                    // Hash is prefixed with the nonce to support user-defined sort order.
                                    std::string hash = std::move(nonce);
                                    // Append the hash of the message signature to get the final hash.
                                    hash.append(sig_hash);

                                    // Keep checking the subtotal of inputs extracted so far with the appbill account balance.
                                    total_input_len += input.length();
                                    if (verify_appbill_check(pubkey, total_input_len))
                                    {
                                        ctx.candidate_user_inputs.try_emplace(
                                            hash,
                                            candidate_user_input(pubkey, std::move(input), maxledgerseqno));
                                    }
                                    else
                                    {
                                        // Abandon processing further inputs from this user when we find out
                                        // an input cannot be processed with the account balance.
                                        appbill_balance_exceeded = true;
                                        reject_reason = jusrmsg::REASON_APPBILL_BALANCE_EXCEEDED;
                                    }
                                }
                                else
                                {
                                    reject_reason = jusrmsg::REASON_APPBILL_BALANCE_EXCEEDED;
                                }
                            }
                            else
                            {
                                LOG_DBG << "User message bad max ledger seq expired.";
                                reject_reason = jusrmsg::REASON_MAX_LEDGER_EXPIRED;
                            }
                        }
                        else
                        {
                            LOG_DBG << "User message bad signature.";
                            reject_reason = jusrmsg::REASON_BAD_SIG;
                        }
                    }
                    else
                    {
                        LOG_DBG << "Duplicate user message.";
                        reject_reason = jusrmsg::REASON_DUPLICATE_MSG;
                    }

                    // Send the request status result if this user is connected to us.
                    if (session != NULL)
                    {
                        usr::send_request_status_result(*session,
                                                        reject_reason == NULL ? jusrmsg::STATUS_ACCEPTED : jusrmsg::STATUS_REJECTED,
                                                        reject_reason == NULL ? "" : reject_reason,
                                                        jusrmsg::MSGTYPE_CONTRACT_INPUT,
                                                        jusrmsg::origin_data_for_contract_input(umsg.sig));
                    }
                }
            }
        }
        p2p::ctx.collected_msgs.nonunl_proposals.clear();
    }

    /**
 * Executes the appbill and verifies whether the user has enough account balance to process the provided input.
 * @param pubkey User binary pubkey.
 * @param input_len Total bytes length of user input.
 * @return Whether the user is allowed to process the input or not.
 */
    bool verify_appbill_check(std::string_view pubkey, const size_t input_len)
    {
        // If appbill not enabled always green light the input.
        if (conf::cfg.appbill.empty())
            return true;

        // execute appbill in --check mode to verify this user can submit a packet/connection to the network
        // todo: this can be made more efficient, appbill --check can process 7 at a time

        // Fill appbill args
        const int len = conf::cfg.runtime_appbill_args.size() + 4;
        char *execv_args[len];
        for (int i = 0; i < conf::cfg.runtime_appbill_args.size(); i++)
            execv_args[i] = conf::cfg.runtime_appbill_args[i].data();
        char option[] = "--check";
        execv_args[len - 4] = option;
        // add the hex encoded public key as the last parameter
        std::string hexpubkey;
        util::bin2hex(hexpubkey, reinterpret_cast<const unsigned char *>(pubkey.data()), pubkey.size());
        std::string inputsize = std::to_string(input_len);
        execv_args[len - 3] = hexpubkey.data();
        execv_args[len - 2] = inputsize.data();
        execv_args[len - 1] = NULL;

        int pid = fork();
        if (pid == 0)
        {
            // before execution chdir into a valid the latest state data directory that contains an appbill.table
            chdir(conf::ctx.state_rw_dir.c_str());
            int ret = execv(execv_args[0], execv_args);
            LOG_ERR << "Appbill process execv failed: " << ret;
            return false;
        }
        else
        {
            // app bill in check mode takes a very short period of time to execute, typically 1ms
            // so we will blocking wait for it here
            int status = 0;
            waitpid(pid, &status, 0); //todo: check error conditions here
            status = WEXITSTATUS(status);
            if (status != 128 && status != 0)
            {
                // this user's key passed appbill
                return true;
            }
            else
            {
                // user's key did not pass, do not add to user input candidates
                LOG_DBG << "Appbill validation failed " << hexpubkey << " return code was " << status;
                return false;
            }
        }
    }

    p2p::proposal create_stage0_proposal()
    {
        // The proposal we are going to emit in stage 0.
        p2p::proposal stg_prop;
        stg_prop.time = ctx.time_now;
        stg_prop.stage = 0;
        stg_prop.lcl = ctx.lcl;
        stg_prop.state = ctx.state;

        // Populate the proposal with set of candidate user pubkeys.
        for (const std::string &pubkey : ctx.candidate_users)
            stg_prop.users.emplace(pubkey);

        // We don't need candidate_users anymore, so clear it. It will be repopulated during next consensus round.
        ctx.candidate_users.clear();

        // Populate the proposal with hashes of user inputs.
        for (const auto &[hash, cand_input] : ctx.candidate_user_inputs)
            stg_prop.hash_inputs.emplace(hash);

        // Populate the proposal with hashes of user outputs.
        for (const auto &[hash, cand_output] : ctx.candidate_user_outputs)
            stg_prop.hash_outputs.emplace(hash);

        // todo: generate stg_prop hash and check with ctx.novel_proposal, we are sending same proposal again.

        return stg_prop;
    }

    p2p::proposal create_stage123_proposal(vote_counter &votes)
    {
        // The proposal to be emited at the end of this stage.
        p2p::proposal stg_prop;
        stg_prop.stage = ctx.stage;

        // we always vote for our current lcl and state regardless of what other peers are saying
        // if there's a fork condition we will either request history and state from
        // our peers or we will halt depending on level of consensus on the sides of the fork
        stg_prop.lcl = ctx.lcl;
        stg_prop.state = ctx.state;

        // Vote for rest of the proposal fields by looking at candidate proposals.
        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
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
 * Broadcasts the given proposal to all connected peers.
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

        // LOG_DBG << "Proposed [stage" << std::to_string(p.stage)
        //         << "] users:" << p.users.size()
        //         << " hinp:" << p.hash_inputs.size()
        //         << " hout:" << p.hash_outputs.size()
        //         << " ts:" << std::to_string(p.time);
    }

    /**
 * Check our LCL is consistent with the proposals being made by our UNL peers lcl_votes.
 */
    void check_lcl_votes(bool &is_desync, bool &should_request_history, std::string &majority_lcl, vote_counter &votes)
    {
        int32_t total_lcl_votes = 0;

        for (const auto &[pubkey, cp] : ctx.candidate_proposals)
        {
            increment(votes.lcl, cp.lcl);
            total_lcl_votes++;
        }

        is_desync = false;
        should_request_history = false;

        if (total_lcl_votes < (MAJORITY_THRESHOLD * conf::cfg.unl.size()))
        {
            LOG_DBG << "Not enough peers proposing to perform consensus. votes:" << std::to_string(total_lcl_votes) << " needed:" << std::to_string(MAJORITY_THRESHOLD * conf::cfg.unl.size());
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

        //if winning lcl is not matched node lcl,
        //that means vote is not on the consensus ledger.
        //Should request history from a peer.
        if (ctx.lcl != majority_lcl)
        {
            LOG_DBG << "We are not on the consensus ledger, requesting history from a random peer";
            is_desync = true;

            //Node is not in sync with current lcl ->switch to observer mode.
            conf::change_operating_mode(conf::OPERATING_MODE::OBSERVER);

            should_request_history = true;
            return;
        }

        if (winning_votes < MAJORITY_THRESHOLD * ctx.candidate_proposals.size())
        {
            // potential fork condition.
            LOG_DBG << "No consensus on lcl. Possible fork condition. won:" << std::to_string(winning_votes) << " total:" << std::to_string(ctx.candidate_proposals.size());
            is_desync = true;
            return;
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

        is_desync = (ctx.state == majority_state);
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

    /**
 * Finalize the ledger after consensus.
 * @param cons_prop The proposal that reached consensus.
 */
    int apply_ledger(const p2p::proposal &cons_prop)
    {
        const std::tuple<const uint64_t, std::string> new_lcl = save_ledger(cons_prop);
        ctx.led_seq_no = std::get<0>(new_lcl);
        ctx.lcl = std::get<1>(new_lcl);

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

        sc::contract_bufmap_t useriobufmap;

        sc::contract_iobuf_pair nplbufpair;
        nplbufpair.inputs.splice(nplbufpair.inputs.end(), ctx.candidate_npl_messages);

        feed_user_inputs_to_contract_bufmap(useriobufmap, cons_prop);

        if (run_contract_binary(cons_prop.time, useriobufmap, nplbufpair) == -1)
            return -1;

        extract_user_outputs_from_contract_bufmap(useriobufmap);
        broadcast_npl_output(nplbufpair.output);
        return 0;
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
                        user.session.send(msg);
                    }
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
                LOG_ERR << "input required but wasn't in our candidate inputs map, this will potentially cause desync.";
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
                //LOG_DBG << "candidate input deleted.";
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

    void broadcast_npl_output(std::string &output)
    {
        if (!output.empty())
        {
            p2p::npl_message npl;
            npl.data.swap(output);

            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2pmsg::create_msg_from_npl_output(fbuf, npl, ctx.lcl);
            p2p::broadcast_message(fbuf, false);
        }
    }

    /**
 * Executes the smart contract with the specified time and provided I/O buf maps.
 * @param time_now The time that must be passed on to the contract.
 * @param useriobufmap The contract bufmap which holds user I/O buffers.
 */
    int run_contract_binary(const int64_t time_now, sc::contract_bufmap_t &useriobufmap, sc::contract_iobuf_pair &nplbufpair)
    {
        // todo:implement exchange of hpsc bufs
        sc::contract_iobuf_pair hpscbufpair;
        return sc::exec_contract(
            sc::contract_exec_args(time_now, useriobufmap, nplbufpair, hpscbufpair),
            ctx.state);
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
