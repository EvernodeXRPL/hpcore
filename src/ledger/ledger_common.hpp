#ifndef _HP_LEDGER_LEDGER_COMMON_
#define _HP_LEDGER_LEDGER_COMMON_

#include "../pchheader.hpp"

namespace ledger
{
    constexpr const char *DATABASE = "ledger.sqlite";
    constexpr uint64_t PRIMARY_SHARD_SIZE = 262144; // 2^18 ledgers per shard.
    constexpr uint64_t BLOB_SHARD_SIZE = 4096;

    /**
     * Struct to hold ledger fields read.
     * All the hashes are stored as hex strings.
    */
    struct ledger_record
    {
        uint64_t seq_no;
        uint64_t timestamp;
        std::string ledger_hash_hex;
        std::string prev_ledger_hash_hex;
        std::string data_hash_hex;
        std::string state_hash_hex;
        std::string config_hash_hex;
        std::string user_hash_hex;
        std::string input_hash_hex;
        std::string output_hash_hex;
    };
}

#endif