
#include <ctime>
#include <unordered_map>
#include <list>
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
    float vote_threshold = cons::STAGE1_THRESHOLD;
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

void consensus()
{
    std::time_t time_now = std::time(nullptr);
    p2p::proposal proposal;

    switch (consensus_ctx.stage)
    {

    case 0: // in stage 0 we create a novel proposal and broadcast it
    {
        // clear out the old stage 3 proposals and any previous proposals made by us
        // todo: check the state of these to ensure we're running consensus ledger
        //consensus_ctx.proposals.erase(std::remove_if);

        for (auto iter = consensus_ctx.proposals.begin(); iter != consensus_ctx.proposals.end();)
        {
            if (iter->stage == 3 || conf::cfg.pubkey == iter->pubkey)
                consensus_ctx.proposals.erase(iter);
        }

        //get user inputs
        for (auto &[sid, user] : usr::users)
        {
            // add all the connections we host
            proposal.users.emplace(user.pubkey);

            // and all their pending messages
            std::string inputtosend;
            inputtosend.swap(user.inbuffer);

            proposal.raw_inputs.try_emplace(user.pubkey, std::move(inputtosend));
        }

        //propose outputs from previous round if any.
        for (auto &[pubkey, bufpair] : local_userbuf)
        {
            if (!bufpair.second.empty())
            {
                proposal.raw_outputs.try_emplace(pubkey, bufpair.second);
            }
        }

        // todo: set propsal states

        consensus_ctx.novel_proposal_time = time_now;
        //todo:generate proposal hash and check with consensus_ctx.novel_proposal, we are sending same proposal again/

        proposal.time = time_now;
        proposal.stage = 0;

        //broadcast proposal to peers
        p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
        p2p::create_msg_from_proposal(msg.builder(), proposal);

        for (auto &[k, session] : p2p::peer_connections)
        {
            session->send(msg);
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

        // check if we're ahead/behind of consensus
        if (wining_stage < consensus_ctx.stage - 1)
        {
            LOG_DBG << "wait for proposals becuase node is ahead of consensus" << wining_stage;
            // LOG_DBG << 'stage votes' << stage_votes ;
            // wait_for_proposals => wait_time = (time - ram.consensus.novel_proposal_time < Math.floor(node.roundtime / 1000)))
        }
        else if (wining_stage > consensus_ctx.stage - 1)
        {
            LOG_DBG << "wait for proposals becuase node is behind of consensus " << wining_stage;
            //return wait_for_proposals =>reset = true
        }

        //todo:check lcl votes and wait for proposals

        //start count votes for other proposal fields.
        for (auto &rc_proposal : consensus_ctx.proposals)
        {
            //vote for proposal timestamps
            // everyone votes on an arbitrary time, as long as its within the round time and not in the future
            if (time_now > rc_proposal.time && time_now - rc_proposal.time < conf::cfg.roundtime)
                increment<uint64_t>(votes.time, rc_proposal.time);

            //vote for user connection
            for (auto user : rc_proposal.users)
                increment<std::string>(votes.users, user);

            //vote for inputs
            if (!rc_proposal.raw_inputs.empty())
            {
                //todo:
                for (auto input : rc_proposal.raw_inputs)
                {
                    std::string possible_input = input.first;
                    possible_input.reserve(input.second.size());
                    possible_input.append(input.second);

                    auto hash = crypto::sha_512_hash(possible_input, "INP", 3);
                    auto input_pair = std::make_pair(input.first, input.second);
                    consensus_ctx.possible_inputs.try_emplace(std::move(hash), std::move(input_pair));
                    increment<std::string>(votes.inputs, hash);
                }
            }
            else if (!rc_proposal.hash_inputs.empty())
            {
                for (auto input : rc_proposal.raw_inputs)
                {
                    increment<std::string>(votes.inputs, input.second);
                }
            }

            //vote for outputs
            if (!rc_proposal.raw_outputs.empty())
            {
                //todo:
                for (auto output : rc_proposal.raw_outputs)
                {
                    std::string possible_output = output.first;
                    possible_output.reserve(output.second.size());
                    possible_output.append(output.second);

                    auto hash = crypto::sha_512_hash(possible_output, "OUT", 3);
                    auto output_pair = std::make_pair(output.first, output.second);
                    consensus_ctx.possible_outputs.try_emplace(std::move(hash), std::move(output_pair));
                    increment<std::string>(votes.outputs, hash);
                }
            }
            else if (!rc_proposal.hash_outputs.empty())
            {
                for (auto output : rc_proposal.raw_outputs)
                {
                    increment<std::string>(votes.outputs, output.second);
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
            if (usr.second >= vote_threshold || (usr.second > 0 && consensus_ctx.stage == 1))
                proposal.users.emplace(usr.first);

        //add inputs which have votes over stage threshold to proposal.
        for (auto input : votes.inputs)
            if (input.second >= vote_threshold || (input.second > 0 && consensus_ctx.stage == 1))
                proposal.hash_inputs.emplace(input.first);

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

        for (auto &[k, session] : p2p::peer_connections)
        {
            session->send(msg);
        }

        if (consensus_ctx.stage == 3)
        {
            apply_ledger(proposal);
        }
    }
    }

    // auto time_to_sleep = conf::cfg.roundtime / 4;
    // std::chrono::milliseconds timespan(time_to_sleep);
    // // after a novel proposal we will just busy wait for proposals
    // if (consensus_ctx.stage > 0)
    //     std::this_thread::sleep_for(timespan);
    // else
    //     usleep(1);
    consensus_ctx.proposals.clear();
    consensus_ctx.stage = (consensus_ctx.stage + 1) % 4;
}

void apply_ledger(p2p::proposal proposal)
{
    //todo:write lcl.

    // first send out any relevant output from the previous consensus round and execution
    for (auto &hash : proposal.hash_outputs)
    {
        auto itr = consensus_ctx.possible_outputs.find(hash);
        if (itr != consensus_ctx.possible_outputs.end())
        {
            LOG_DBG << "output required" << hash << "but wasn't in our possible output dict, this will potentially cause desync";
            // todo: consider fatal
        }
        else
        {
            auto output = itr->second.second;
            //send outputs.
            const std::string sessionid = usr::sessionids[itr->second.first];
            // Find the user by session id.
            auto itr = usr::users.find(sessionid);
            const usr::connected_user &user = itr->second;
            user.session->send(std::move(output));
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
        if (itr != consensus_ctx.possible_inputs.end())
        {
            LOG_DBG << "input required" << hash << "but wasn't in our possible input dict, this will potentially cause desync";
            // todo: consider fatal
        }
        else
        {
            //todo: check if the pending input for this user contains any more data  and remove them.

            for (auto &input : consensus_ctx.possible_inputs)
            {
                std::pair<std::string, std::string> bufpair;
                std::string inputtosend;
                inputtosend.swap(input.second.second);
                bufpair.first = std::move(inputtosend);
                local_userbuf.emplace(input.second.first, std::move(bufpair));
            }
        }
    }

    consensus_ctx.possible_inputs.empty();
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