#ifndef _HP_HPFS_CONTRACT_SERVE_
#define _HP_HPFS_CONTRACT_SERVE_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "./hpfs_serve.hpp"

namespace hpfs
{
    class contract_serve : public hpfs_serve
    {
    private:
        void swap_collected_requests();
    };
} // namespace hpfs
#endif