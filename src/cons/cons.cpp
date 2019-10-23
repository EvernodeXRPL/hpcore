
#include <ctime>
#include <unordered_map>
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../p2p/p2p.hpp"
#include "../hplog.hpp"
#include "../crypto.hpp"
#include "cons.hpp"

namespace cons
{

consensus_context consensus_ctx;
std::vector<p2p::proposal> consensus_proposals;

template <typename T>
void increment(std::unordered_map<T, int32_t> &counter, T &candidate)
{
    if (counter.count(candidate))
        counter[candidate]++;

    else
        counter.try_emplace(candidate, 1);
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
        std::unordered_map<std::string, std::string> user_inputs;
        for (auto &[sid, user] : usr::users)
        {
            // add all the connections we host
            proposal.users.emplace_back(user.pubkey);

            // and all their pending messages
            std::string inputtosend;
            inputtosend.swap(user.inbuffer);

            user_inputs.try_emplace(user.pubkey, std::move(inputtosend));
        }

        // todo:propose outputs from previous round if any
        //  for (var user in ram.consensus.local_output_dict)
        //         proposal.out[user] = ram.consensus.local_output_dict[user]

        // todo: set propsal states

        consensus_ctx.novel_proposal_time = time_now;
        //todo:generate proposal hash and check with consensus_ctx.novel_proposal, we are sending same proposal again/

        proposal.time = time_now;

        //broadcast_to_peers(sign_peer_message(proposal).signed)
        break;
    }
    case 1:
    case 2:
    case 3:
    {
        //copy proposals
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
                    consensus_ctx.possible_inputs.try_emplace(hash, input.first);
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
                    consensus_ctx.possible_outputs.try_emplace(hash, output.first);
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

        float vote_threshold = cons::STAGE1_THRESHOLD;
        switch (consensus_ctx.stage)
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

        // todo: check if inputs being proposed by another node are actually spoofed inputs
        // from a user locally connected to this node.

        // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote.

        //add user connections which have votes over stage threshold to proposal.
        for (auto usr : votes.users)
            if (usr.second >= vote_threshold || (usr.second > 0 && consensus_ctx.stage == 1))
                proposal.users.emplace_back(usr.first);

        //add inputs which have votes over stage threshold to proposal.
        for (auto input : votes.inputs)
            if (input.second >= vote_threshold || (input.second > 0 && consensus_ctx.stage == 1))
                proposal.hash_inputs.emplace_back(input.first);

        //add outputs which have votes over stage threshold to proposal.
        for (auto output : votes.outputs)
            if (output.second >= vote_threshold)
                proposal.hash_outputs.emplace_back(output.first);

        //todo:add states which have votes over stage threshold to proposal.

        // time is voted on a simple sorted and majority basis, since there will always be disagreement.
        int32_t largest_vote = 0;
        for (auto &time : votes.time)
        {
            if (time.second > largestvote)
            {
                largestvote = time.second;
                proposal.time = time.first;
            }
        }

        // we always vote for our current lcl regardless of what other peers are saying
        // if there's a fork condition we will either request history and state from
        // our peers or we will halt depending on level of consensus on the sides of the fork
        proposal.lcl = consensus_ctx.lcl;

        //send proposal
        //1.create flatbuffer content.
        //2.sign message
        //3.create container.
        //4. broadcast tha message.

        if (consensus_ctx.stage == 3)
        {
            // apply_ledger(proposal)
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

    consensus_ctx.stage = (consensus_ctx.stage + 1) % 4;
}

} // namespace cons