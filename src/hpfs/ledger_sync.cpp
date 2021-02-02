
#include "./ledger_sync.hpp"

namespace hpfs
{
    void ledger_sync::on_current_sync_state_acheived()
    {
        // Logic when a sync state is acheived can be performed here.
    }

    void ledger_sync::swap_collected_responses()
    {
        std::scoped_lock lock(p2p::ctx.collected_msgs.ledger_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_responses.empty())
            ctx.candidate_hpfs_responses.splice(ctx.candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.ledger_hpfs_responses);
    }
} // namespace hpfs