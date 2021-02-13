
#include "./ledger_sync.hpp"
#include "ledger.hpp"

namespace ledger
{
    constexpr const char *HPFS_SESSION_NAME = "ro_shard_sync_status";

    void ledger_sync::on_sync_complete(const hpfs::sync_target &last_sync_target)
    {

        LOG_INFO << "Hpfs " << name << " sync: All parents synced.";
        is_ledger_shard_desync = false;
        get_last_ledger();
    }

    void ledger_sync::on_sync_abandoned()
    {
        // Reset shard sync status.
        is_ledger_shard_desync = false;
    }

    void ledger_sync::swap_collected_responses()
    {
        std::scoped_lock lock(p2p::ctx.collected_msgs.ledger_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_responses.empty())
            candidate_hpfs_responses.splice(candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.ledger_hpfs_responses);
    }

} // namespace ledger