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
        void on_sync_abandoned();
        void swap_collected_responses();
        void on_sync_complete(const hpfs::sync_target &last_sync_target);

    public:
        std::atomic<bool> is_ledger_shard_desync = false;
    };
} // namespace ledger
#endif