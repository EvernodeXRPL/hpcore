
#include "./ledger_sync.hpp"
#include "ledger.hpp"

namespace ledger
{
    void ledger_sync::on_current_sync_state_acheived(const util::h32 &acheived_hash)
    {
        // Logic when a sync state is acheived can be performed here.
        if (current_target.vpath == hpfs::LEDGER_PRIMARY_SHARD_INDEX_PATH)
        {
            ledger_fs.set_parent_hash(current_target.vpath, acheived_hash);
        }

        get_last_ledger();
    }

    void ledger_sync::swap_collected_responses()
    {
        std::scoped_lock lock(p2p::ctx.collected_msgs.ledger_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_responses.empty())
            candidate_hpfs_responses.splice(candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.ledger_hpfs_responses);
    }
} // namespace ledger