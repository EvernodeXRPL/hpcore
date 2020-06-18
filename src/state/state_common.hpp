#ifndef _HP_CONS_STATE_COMMON_
#define _HP_CONS_STATE_COMMON_

#include "../pchheader.hpp"
#include "../conf.hpp"

namespace state_common
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB;

    inline uint16_t get_request_resubmit_timeout()
    {
        return conf::cfg.roundtime;
    }
}

#endif