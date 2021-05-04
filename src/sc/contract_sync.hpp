#ifndef _HP_SC_CONTRACT_SYNC_
#define _HP_SC_CONTRACT_SYNC_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_sync.hpp"

namespace sc
{
    class contract_sync : public hpfs::hpfs_sync
    {
    private:
        void on_sync_target_acheived(const hpfs::sync_target &synced_target);
        void swap_collected_responses();
    };
} // namespace sc
#endif