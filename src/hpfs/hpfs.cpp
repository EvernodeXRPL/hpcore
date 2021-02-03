#include "./hpfs.hpp"
#include "../conf.hpp"
#include "./hpfs_serve.hpp"

namespace hpfs
{
    hpfs::hpfs_mount contract_fs;  // Global contract file system instance.
    hpfs::hpfs_sync contract_sync; // Global contract file system sync instance.
    hpfs::hpfs_serve contract_serve;

    /**
     * Initialize necessary file system mounts to hpcore.
    */
    int init()
    {
        if (contract_fs.init(CONTRACT_FS_ID, conf::ctx.hpfs_dir, conf::ctx.hpfs_mount_dir, conf::ctx.hpfs_rw_dir, conf::cfg.node.full_history) == -1)
        {
            LOG_ERROR << "Contract file system initialization failed.";
            return -1;
        }

        if (contract_serve.init("contract", &contract_fs) == -1)
        {
            LOG_ERROR << "Contract file system serve worker initialization failed.";
            return -1;
        }

        if (contract_sync.init("contract", &contract_fs) == -1)
        {
            LOG_ERROR << "Contract file system sync worker initialization failed.";
            return -1;
        }

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

} // namespace hpfs