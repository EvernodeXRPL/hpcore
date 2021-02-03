#ifndef _HP_HPFS_HPFS
#define _HP_HPFS_HPFS

#include "./hpfs_mount.hpp"
#include "../contract/contract_mount.hpp"
#include "../ledger/ledger_mount.hpp"
#include "../contract/contract_sync.hpp"
#include "../ledger/ledger_sync.hpp"

namespace hpfs
{
    constexpr int32_t CONTRACT_FS_ID = 0;
    constexpr int32_t LEDGER_FS_ID = 1;

    extern sc::contract_mount contract_fs;         // Global contract file system instance.
    extern sc::contract_sync contract_sync_worker; // Global contract file system sync instance.
    extern ledger::ledger_mount ledger_fs;             // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker;     // Global ledger file system sync instance.

    int init();
    void deinit();

} // namespace hpfs
#endif