
#include <ctime>
#include <unordered_map>
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../p2p/p2p.hpp"
#include "../hplog.hpp"
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


            //vote for outputs
        }
    }
    }
}

} // namespace cons