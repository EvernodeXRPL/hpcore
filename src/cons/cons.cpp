
#include <ctime>
#include "../conf.hpp"
#include "../usr/usr.hpp"
#include "../p2p/p2p.hpp"
#include "cons.hpp"

namespace cons
{

consensus_context consensus_ctx;
std::vector<p2p::Proposal> consensus_proposals;

void consensus()
{
    std::time_t time_now = std::time(nullptr);
    p2p::Proposal proposal;

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


    }
    }
}

} // namespace cons