
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

consensus_context consensus_ctx;
std::vector<p2p::proposal> consensus_proposals;
std::map<std::string, std::pair<const std::string, const std::string>> local_inputs;
std::unordered_map<std::string, std::pair<std::string, std::string>> local_userbuf;

template <typename T>
void increment(std::unordered_map<T, int32_t> &counter, const T &candidate)
{
    if (counter.count(candidate))
        counter[candidate]++;
    else
        counter.try_emplace(candidate, 1);
}

float get_stage_threshold(int8_t stage)
{
    float vote_threshold = -1;
    switch (stage)
    {
    case 1:
        vote_threshold = cons::STAGE1_THRESHOLD * conf::cfg.unl.size();
        break;
    case 2:
        vote_threshold = cons::STAGE2_THRESHOLD * conf::cfg.unl.size();
        break;
    case 3:
        vote_threshold = cons::STAGE3_THRESHOLD * conf::cfg.unl.size();
        break;
    }
    return vote_threshold;
}

void wait_for_proposals(bool reset)
{
    if (reset)
        consensus_ctx.stage = 0;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void consensus()
{
    std::time_t time_now = std::time(nullptr);
    p2p::proposal proposal;
    proposal.stage = consensus_ctx.stage;

    switch (consensus_ctx.stage)
    {

    case 0: // in stage 0 we create a novel proposal and broadcast it
    {
        // clear out the old stage 3 proposals and any previous proposals made by us
        // todo: check the state of these to ensure we're running consensus ledger
        //consensus_ctx.proposals.erase(std::remove_if);

        {
            std::lock_guard<std::mutex> lock(p2p::collected_msgs.proposals_mutex);

            auto itr = p2p::collected_msgs.proposals.begin();
            while (itr != p2p::collected_msgs.proposals.end())
            {
                if (itr->stage == 3 || conf::cfg.pubkey == itr->pubkey)
                    p2p::collected_msgs.proposals.erase(itr++);
                else
                    ++itr;
            }
        }

        //get user inputs
        {
            std::lock_guard<std::mutex> lock(usr::users_mutex);
            for (auto &[sid, user] : usr::users)
            {
                // add all the connections we host
                proposal.users.emplace(user.pubkey);

                // and all their pending messages
                std::string input;
                input.swap(user.inbuffer);

                if (!input.empty())
                    proposal.raw_inputs.try_emplace(user.pubkey, std::move(input));
            }
        }

        //propose outputs from previous round if any.
        for (auto &[pubkey, bufpair] : local_userbuf)
        {
            LOG_DBG << "local_userbuf:[" << bufpair.second.size() << "]";

            if (!bufpair.second.empty()) // bufpair.second is the output buffer.
            {
                std::string rawoutput;
                rawoutput.swap(bufpair.second);
                proposal.raw_outputs.try_emplace(pubkey, std::move(rawoutput));
            }
        }
        local_userbuf.clear();

        // todo: set propsal states

        consensus_ctx.novel_proposal_time = time_now;
        //todo:generate proposal hash and check with consensus_ctx.novel_proposal, we are sending same proposal again/
        proposal.lcl = consensus_ctx.lcl;
        proposal.time = time_now;

        //broadcast proposal to peers
        p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
        p2p::create_msg_from_proposal(msg.builder(), proposal);

        {
            std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
            for (auto &[k, session] : p2p::peer_connections)
            {
                LOG_WARN << "Sending proposal to: " << session->uniqueid;
                session->send(msg);
            }
        }

        break;
    }
    case 1:
    case 2:
    case 3:
    {
        //copy proposals
        consensus_ctx.proposals.swap(p2p::collected_msgs.proposals);
        //consensus_ctx.proposals = ;

        //vote counters
        cons::vote_counter votes;

        for (auto &rc_proposal : consensus_ctx.proposals)
        {
            //vote stages if only proposal lcl is match with node's last consensus lcl
            if (proposal.lcl == consensus_ctx.lcl)
            {
                //std::string rp_state = std::to_string(rc_proposal.stage);
                increment<int8_t>(votes.stage, rc_proposal.stage);
                LOG_WARN << "Incremented stage vote: " << std::to_string(rc_proposal.stage) << " votes:" << votes.stage[rc_proposal.stage];
            }
            //todo:vote for lcl checking condtion
        }

        int32_t largestvote = 0;
        int8_t wining_stage = -1;

        for (auto &stage : votes.stage)
        {
            if (stage.second > largestvote)
            {
                largestvote = stage.second;
                wining_stage = stage.first;
            }
        }

        LOG_DBG << "wining_stage: " << std::to_string(wining_stage);

        // check if we're ahead/behind of consensus
        if (wining_stage < consensus_ctx.stage - 1)
        {
            LOG_DBG << "wait for proposals becuase node is ahead of consensus stage:" << std::to_string(wining_stage);
            // LOG_DBG << 'stage votes' << stage_votes ;
            return wait_for_proposals((time_now - consensus_ctx.novel_proposal_time) < floor(conf::cfg.roundtime / 4));
        }
        else if (wining_stage > consensus_ctx.stage - 1)
        {
            LOG_DBG << "wait for proposals becuase node is behind of consensus " << wining_stage;
            return wait_for_proposals(true);
            //return wait_for_proposals =>reset = true
        }

        //todo:check lcl votes and wait for proposals

        //start count votes for other proposal fields.
        for (auto &rc_proposal : consensus_ctx.proposals)
        {
            //vote for proposal timestamps
            // everyone votes on an arbitrary time, as long as its within the round time and not in the future
            if (time_now > rc_proposal.time && time_now - rc_proposal.time < conf::cfg.roundtime)
            {
                increment<uint64_t>(votes.time, rc_proposal.time);
                LOG_WARN << "Incremented time: " << rc_proposal.time << " votes:" << votes.time[rc_proposal.time];
            }

            //vote for user connection
            for (auto user : rc_proposal.users)
            {
                std::string str;
                util::bin2hex(str, (unsigned char *)user.data(), user.length());
                increment<std::string>(votes.users, user);
                LOG_WARN << "Incremented user: " << str << " votes:" << votes.users[user];
            }

            //vote for inputs
            if (!rc_proposal.raw_inputs.empty())
            {
                //todo:
                for (auto &[pubkey, input] : rc_proposal.raw_inputs)
                {
                    std::string possible_input;
                    possible_input.reserve(pubkey.size() + input.size());
                    possible_input.append(pubkey);
                    possible_input.append(input);

                    auto hash = crypto::sha_512_hash(possible_input, "INP", 3);
                    increment<std::string>(votes.inputs, hash);

                    LOG_DBG << "Added hashsize: " << hash.size() << " with input: " << input;
                    consensus_ctx.possible_inputs.try_emplace(
                        std::move(hash),
                        std::make_pair(pubkey, input));
                }
            }
            else if (!rc_proposal.hash_inputs.empty())
            {
                for (auto inputhash : rc_proposal.hash_inputs)
                {
                    increment<std::string>(votes.inputs, inputhash);
                }
            }

            //vote for outputs
            if (!rc_proposal.raw_outputs.empty())
            {
                //todo:
                for (auto &[pubkey, output] : rc_proposal.raw_outputs)
                {
                    std::string string_to_hash;
                    string_to_hash.reserve(pubkey.size() + output.size());
                    string_to_hash.append(pubkey);
                    string_to_hash.append(output);

                    LOG_DBG << "raw_outputs:[" << output.size() << "]";

                    std::string hash = crypto::sha_512_hash(string_to_hash, "OUT", 3);
                    increment<std::string>(votes.outputs, hash);

                    consensus_ctx.possible_outputs.try_emplace(
                        std::move(hash),
                        std::make_pair(pubkey, output));
                }
            }
            else if (!rc_proposal.hash_outputs.empty())
            {
                for (auto outputhash : rc_proposal.hash_outputs)
                {
                    increment<std::string>(votes.outputs, outputhash);
                }
            }

            // repeat above for state
        }

        float vote_threshold = get_stage_threshold(consensus_ctx.stage);

        // todo: check if inputs being proposed by another node are actually spoofed inputs
        // from a user locally connected to this node.

        // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

        //add user connections which have votes over stage threshold to proposal.
        for (auto usr : votes.users)
        {
            if (usr.second >= vote_threshold || (usr.second > 0 && consensus_ctx.stage == 1))
                proposal.users.emplace(usr.first);
        }
        //add inputs which have votes over stage threshold to proposal.
        for (auto &[hash, count] : votes.inputs)
        {
            if (count >= vote_threshold || (count > 0 && consensus_ctx.stage == 1))
                proposal.hash_inputs.emplace(hash);
        }
        //add outputs which have votes over stage threshold to proposal.
        for (auto output : votes.outputs)
            if (output.second >= vote_threshold)
                proposal.hash_outputs.emplace(output.first);

        //todo:add states which have votes over stage threshold to proposal.

        // time is voted on a simple sorted and majority basis, since there will always be disagreement.
        int32_t largest_vote = 0;
        for (auto &time : votes.time)
        {
            if (time.second > largestvote)
            {
                largest_vote = time.second;
                proposal.time = time.first;
            }
        }

        // we always vote for our current lcl regardless of what other peers are saying
        // if there's a fork condition we will either request history and state from
        // our peers or we will halt depending on level of consensus on the sides of the fork
        proposal.lcl = consensus_ctx.lcl;

        //send proposal
        p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
        p2p::create_msg_from_proposal(msg.builder(), proposal);

        LOG_DBG << "Stage (" << std::to_string(consensus_ctx.stage)
                << ") Proposed users:" << proposal.users.size()
                << " rinputs:" << proposal.raw_inputs.size()
                << " hinputs:" << proposal.hash_inputs.size()
                << " routs:" << proposal.raw_outputs.size()
                << " houts:" << proposal.hash_outputs.size();

        {
            std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
            for (auto &[k, session] : p2p::peer_connections)
                session->send(msg);
        }

        if (consensus_ctx.stage == 3)
        {
            LOG_DBG << "stage 3 output" << proposal.hash_inputs.size();
            apply_ledger(proposal);
        }
    }
    }

    auto time_to_sleep = conf::cfg.roundtime / 4;
    
    // // after a novel proposal we will just busy wait for proposals
    if (consensus_ctx.stage > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(time_to_sleep));
    else
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    consensus_ctx.proposals.clear();
    consensus_ctx.stage = (consensus_ctx.stage + 1) % 4;
}

void apply_ledger(p2p::proposal proposal)
{
    //todo:write lcl.

    LOG_DBG << "possible_outputs: " << consensus_ctx.possible_outputs.size();
    // first send out any relevant output from the previous consensus round and execution
    for (auto &hash : proposal.hash_outputs)
    {
        auto itr = consensus_ctx.possible_outputs.find(hash);
        if (itr == consensus_ctx.possible_outputs.end())
        {
            LOG_DBG << "output required but wasn't in our possible output dict, this will potentially cause desync";
            // todo: consider fatal
        }
        else
        {
            //send outputs.
            LOG_DBG << "A";
            auto &[pubkey, output] = itr->second;
            std::string outputtosend;
            outputtosend.swap(output);
            LOG_DBG << "B";

            {
                std::lock_guard<std::mutex> lock(usr::users_mutex);

                // Find the user by session id.
                const std::string sessionid = usr::sessionids[pubkey];
                auto itr = usr::users.find(sessionid);
                if (itr != usr::users.end())
                {
                    const usr::connected_user &user = itr->second;

                    LOG_DBG << "C [" << outputtosend << "]";

                    usr::user_outbound_message outmsg(std::move(outputtosend));
                    LOG_DBG << "D";

                    user.session->send(std::move(outmsg));
                    LOG_DBG << "E";
                }
            }
        }
    }

    // now we can safely clear our outputs.
    consensus_ctx.possible_outputs.empty();

    //todo:check  state against the winning / canonical state
    //and act accordingly (rollback, ask state from peer, etc.)

    //create input to feed to binary contract run

    //todo:remove entries from pending inputs that made their way into a closed ledger
    for (auto &hash : proposal.hash_inputs)
    {
        auto itr = consensus_ctx.possible_inputs.find(hash);
        if (itr == consensus_ctx.possible_inputs.end())
        {
            LOG_DBG << "input required hashsize:" << hash.size() << " but wasn't in our possible input dict, this will potentially cause desync";
            // todo: consider fatal
        }
        else
        {
            //todo: check if the pending input for this user contains any more data  and remove them.

            for (auto &[hash, userinput] : consensus_ctx.possible_inputs)
            {
                std::pair<std::string, std::string> bufpair;
                std::string inputtosend;
                inputtosend.swap(userinput.second);
                bufpair.first = std::move(inputtosend);
                LOG_DBG << "local_userbuf count: " << local_userbuf.size();
                local_userbuf.try_emplace(userinput.first, std::move(bufpair));
            }
            consensus_ctx.possible_inputs.empty();
        }
    }

    run_contract_binary();
}

void run_contract_binary()
{
    //consensus_ctx.possible_inputs
    std::time_t time_now = std::time(nullptr);
    std::pair<std::string, std::string> hpscbufpair;
    hpscbufpair.first = "{msg:'Message from HP'}";

    std::unordered_map<std::string, std::pair<std::string, std::string>> nplbufs;

    proc::ContractExecArgs eargs(123123345, local_userbuf, nplbufs, hpscbufpair);
    proc::exec_contract(eargs);
}

} // namespace cons