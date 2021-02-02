#ifndef _HP_HPFS_LEDGER_SERVE_
#define _HP_HPFS_LEDGER_SERVE_

#include "../pchheader.hpp"
#include "./hpfs_serve.hpp"

namespace hpfs
{
    class ledger_serve : public hpfs_serve
    {
    private:
        void swap_collected_requests();
    };
} // namespace hpfs
#endif