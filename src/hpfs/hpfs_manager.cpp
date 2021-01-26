#include "./hpfs_manager.hpp"
#include "../conf.hpp"

namespace hpfs_manager
{
    hpfs::hpfs_mount contract_fs; // Global contract file system instance. 

    /**
     * Initialize necessary file system mounts to hpcore.
    */
    int init()
    {
        if (contract_fs.init(conf::ctx.hpfs_dir, conf::ctx.hpfs_mount_dir, conf::ctx.hpfs_rw_dir, conf::cfg.node.full_history) == -1)
            return -1;

        return 0;
    }

    /**
     * Perform cleanups on created mounts.
    */
    void deinit()
    {
        contract_fs.deinit();
    }

} // namespace hpfs_manager