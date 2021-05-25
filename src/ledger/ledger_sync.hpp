#ifndef _HP_LEDGER_LEDGER_SYNC_
#define _HP_LEDGER_LEDGER_SYNC_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_sync.hpp"

namespace ledger
{
    class ledger_sync : public hpfs::hpfs_sync
    {
    private:
        void swap_collected_responses();
        void on_sync_target_acheived(const std::string &vpath, const util::h32 &hash);
        void on_sync_abandoned();

    public:
        std::atomic<bool> is_last_primary_shard_syncing = false;
        std::atomic<bool> is_last_raw_shard_syncing = false;
    };
} // namespace ledger
#endif