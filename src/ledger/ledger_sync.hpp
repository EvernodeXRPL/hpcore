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
        void on_current_sync_state_acheived(const util::h32 &acheived_hash);
        void swap_collected_responses();
    };
} // namespace ledger
#endif