#ifndef _HP_HPFS_LEDGER_SYNC_
#define _HP_HPFS_LEDGER_SYNC_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "./hpfs_sync.hpp"

namespace hpfs
{
    class ledger_sync : public hpfs_sync
    {
    private:
        void on_current_sync_state_acheived();
        void swap_collected_responses();
    };
} // namespace hpfs
#endif