#ifndef _HP_STATE_STATE_COMMON_
#define _HP_STATE_STATE_COMMON_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../util/h32.hpp"

namespace state_common
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB;

    inline uint16_t get_request_resubmit_timeout()
    {
        return conf::cfg.contract.roundtime;
    }

    struct state_context
    {
    private:
        util::h32 state;
        std::shared_mutex state_mutex;

    public:
        util::h32 get_state()
        {
            std::shared_lock lock(state_mutex);
            return state;
        }

        void set_state(util::h32 new_state)
        {
            std::unique_lock lock(state_mutex);
            state = new_state;
        }
    };

    extern state_context ctx;

    int init();

} // namespace state_common

#endif