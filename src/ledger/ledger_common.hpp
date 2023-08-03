#ifndef _HP_LEDGER_LEDGER_COMMON_
#define _HP_LEDGER_LEDGER_COMMON_

#include "../pchheader.hpp"
#include "../util/h32.hpp"

namespace ledger
{
    constexpr const char *PRIMARY_DB = "ledger.sqlite";
    constexpr const char *RAW_DB = "raw.sqlite";
    constexpr const char *RAW_INPUTS_FILE = "raw_inputs.blob";
    constexpr const char *RAW_OUTPUTS_FILE = "raw_outputs.blob";
    constexpr uint64_t PRIMARY_SHARD_SIZE = 262144; // 2^18 ledgers per shard.
    constexpr uint64_t RAW_SHARD_SIZE = 4096;
    constexpr size_t ROUND_NONCE_SIZE = 64;

    /**
     * Holds an individual input for a user within a ledger.
     */
    struct ledger_user_input
    {
        uint64_t ledger_seq_no; // Ledger seq no.
        std::string pubkey;     // The user pubkey.
        std::string hash;       // The hash of this input.
        uint64_t nonce;         // Nonce the user had submitted for this input.
        off_t blob_offset;      // Blob file offset of this input blob.
        size_t blob_size;       // Length of the input.
        std::string blob;       // The actual input blob.
    };

    /**
     * Holds all the outputs for an indivudual user within a ledger.
     */
    struct ledger_user_output
    {
        uint64_t ledger_seq_no;           // Ledger seq no.
        std::string pubkey;               // The user pubkey.
        std::string hash;                 // Combined output hash for this user's outputs.
        off_t blob_offset;                // Blob file offset of the output group header.
        size_t blob_count;                // How many outputs the user has within this ledger.
        std::vector<std::string> outputs; // The actual output blobs for this user within the ledger.
    };

    /**
     * Struct to hold ledger fields corresponding to sqlite table.
     * All the hashes are stored as 32 byte binary data.
     */
    struct ledger_record
    {
        uint64_t seq_no = 0;
        uint64_t timestamp = 0;
        std::string ledger_hash;

        // COntributing hashes.
        std::string prev_ledger_hash;
        std::string data_hash;
        std::string state_hash;
        std::string config_hash;
        std::string nonce;
        std::string user_hash;
        std::string input_hash;
        std::string output_hash;

        // Raw data.
        std::optional<std::vector<ledger_user_input>> inputs;
        std::optional<std::vector<ledger_user_output>> outputs;
    };

    // Holds the global genesis ledger.
    extern ledger_record genesis;
}

#endif