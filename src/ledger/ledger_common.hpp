#ifndef _HP_LEDGER_LEDGER_COMMON_
#define _HP_LEDGER_LEDGER_COMMON_

#include "../pchheader.hpp"
#include "../util/h32.hpp"

namespace ledger
{
    constexpr const char *PRIMARY_DB = "ledger.sqlite";
    constexpr const char *RAW_DB = "raw.sqlite";
    constexpr uint64_t PRIMARY_SHARD_SIZE = 262144; // 2^18 ledgers per shard.
    constexpr uint64_t RAW_SHARD_SIZE = 4096;

    /**
     * Struct to hold ledger fields corresponding to sqlite table.
     * All the hashes are stored as 32 byte binary data.
    */
    struct ledger_record
    {
        uint64_t seq_no = 0;
        uint64_t timestamp = 0;
        std::string ledger_hash;
        std::string prev_ledger_hash;
        std::string data_hash;
        std::string state_hash;
        std::string config_hash;
        std::string user_hash;
        std::string input_hash;
        std::string output_hash;
    };

    // Holds the global genesis ledger.
    extern ledger_record genesis;
}

#endif