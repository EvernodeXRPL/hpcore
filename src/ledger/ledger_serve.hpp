#ifndef _HP_LEDGER_LEDGER_SERVE_
#define _HP_LEDGER_LEDGER_SERVE_

#include "../pchheader.hpp"
#include "../hpfs/hpfs_serve.hpp"

namespace ledger
{
    class ledger_serve : public hpfs::hpfs_serve
    {
    private:
        void swap_collected_requests();
    };
} // namespace ledger
#endif