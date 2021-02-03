#include "../pchheader.hpp"
#include "./hpfs.hpp"
#include "../conf.hpp"
#include "./contract_serve.hpp"
#include "./ledger_serve.hpp"

namespace hpfs
{
    hpfs::contract_mount contract_fs;         // Global contract file system instance.
    hpfs::contract_sync contract_sync_worker; // Global contract file system sync instance.
    hpfs::contract_serve contract_server;     // Contract file server instance.
    hpfs::ledger_mount ledger_fs;             // Global ledger file system instance.
    hpfs::ledger_sync ledger_sync_worker;     // Global ledger file system sync instance.
    hpfs::ledger_serve ledger_server;         // Ledger file server instance.

    /**
     * Initialize necessary file system mounts to hpcore.
    */
    int init()
    {
        if (contract_fs.init(CONTRACT_FS_ID, conf::ctx.contract_hpfs_dir, conf::ctx.contract_hpfs_mount_dir, conf::ctx.contract_hpfs_rw_dir, conf::cfg.node.full_history) == -1)
        {
            LOG_ERROR << "Contract file system initialization failed.";
            return -1;
        }

        if (contract_server.init("contract", &contract_fs) == -1)
        {
            LOG_ERROR << "Contract file system serve worker initialization failed.";
            return -1;
        }

        if (contract_sync_worker.init("contract", &contract_fs) == -1)
        {
            LOG_ERROR << "Contract file system sync worker initialization failed.";
            return -1;
        }

        if (ledger_fs.init(LEDGER_FS_ID, conf::ctx.ledger_hpfs_dir, conf::ctx.ledger_hpfs_mount_dir, conf::ctx.ledger_hpfs_rw_dir, conf::cfg.node.full_history) == -1)
        {
            LOG_ERROR << "Ledger file system initialization failed.";
            return -1;
        }

        if (ledger_server.init("ledger", &ledger_fs) == -1)
        {
            LOG_ERROR << "Ledger file system serve worker initialization failed.";
            return -1;
        }

        if (ledger_sync_worker.init("ledger", &ledger_fs) == -1)
        {
            LOG_ERROR << "Ledger file system sync worker initialization failed.";
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
        contract_server.deinit();
        contract_sync_worker.deinit();

        ledger_fs.deinit();
        ledger_server.deinit();
        ledger_sync_worker.deinit();
    }

} // namespace hpfs