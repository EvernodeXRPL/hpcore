#ifndef _HP_SC_CONTRACT_SERVE_
#define _HP_SC_CONTRACT_SERVE_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_serve.hpp"

namespace sc
{
    class contract_serve : public hpfs::hpfs_serve
    {
    private:
        void swap_collected_requests();
    };
} // namespace sc
#endif