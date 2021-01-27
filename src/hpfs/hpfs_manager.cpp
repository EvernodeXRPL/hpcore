#include "./hpfs_manager.hpp"
#include "../conf.hpp"
#include "./hpfs_serve.hpp"

namespace hpfs_manager
{
    hpfs::hpfs_mount contract_fs; // Global contract file system instance. 
    hpfs::hpfs_serve contract_serve;
    hpfs::hpfs_sync contract_sync;

    /**
     * Initialize necessary file system mounts to hpcore.
    */
    int init()
    {
        if (contract_fs.init(hpfs::MOUNTS::CONTRACT, conf::ctx.hpfs_dir, conf::ctx.hpfs_mount_dir, conf::ctx.hpfs_rw_dir, conf::cfg.node.full_history) == -1)
            return -1;

        if (contract_serve.init("contract", &contract_fs) == -1)
            return -1;

        if (contract_sync.init("contract", &contract_fs) == -1)
            return -1;

        return 0;
    }

    /**
     * Perform cleanups on created mounts.
    */
    void deinit()
    {
        contract_fs.deinit();
        contract_serve.deinit();
        contract_sync.deinit();
    }

} // namespace hpfs_manager