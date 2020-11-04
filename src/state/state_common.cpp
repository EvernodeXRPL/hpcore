#include "state_common.hpp"
#include "../hpfs/hpfs.hpp"
#include "../hplog.hpp"

namespace state_common
{
    state_context ctx;

    /**
     * Get the contract state hash.
     */
    int init()
    {
        hpfs::h32 initial_state;
        if (hpfs::start_fs_session(conf::ctx.state_rw_dir) == -1 ||
            hpfs::get_hash(initial_state, conf::ctx.state_rw_dir, "/") == -1 ||
            hpfs::stop_fs_session(conf::ctx.state_rw_dir) == -1)
        {
            LOG_ERROR << "Failed to get initial state hash.";
            return -1;
        }

        ctx.set_state(initial_state);
        LOG_INFO << "Initial state: " << initial_state;
        
        return 0;
    }
} // namespace state_common