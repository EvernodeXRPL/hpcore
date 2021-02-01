
#include "ledger_sample.hpp"
#include "../crypto.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"

// Currently this namespace is added for sqlite testing, later this can be modified and renamed as 'ledger::ledger_sample' -> 'ledger' for ledger implementations.
namespace ledger::ledger_sample
{
    /**
     * Create and save ledger record from the given proposal message.
     * @param proposal Consensus-reached Stage 3 proposal.
     */
    int save_ledger(const p2p::proposal &proposal)
    {
        sqlite3 *db;

        // For testing purpose a database file is created in directory root.
        if (sqlite::open_db("ledger.sqlite", &db) == -1)
        {
            sqlite3_close(db);
            return -1;
        }

        if (!sqlite::is_ledger_table_exist(db) && sqlite::create_ledger_table(db) == -1)
        {
            sqlite3_close(db);
            return -1;
        }

        uint64_t seq_no = 0;
        std::string hash;
        if (extract_lcl(proposal.lcl, seq_no, hash) == -1)
        {
            // lcl records should follow [ledger sequnce numer]-[lcl hex] format.
            LOG_ERROR << "Invalid lcl name: " << proposal.lcl << " when saving ledger.";
            return -1;
        }

        seq_no++; // New lcl sequence number.

        // Serialize lcl using flatbuffer ledger block schema.
        flatbuffers::FlatBufferBuilder builder(1024);
        msg::fbuf::ledger::create_ledger_block_from_proposal(builder, proposal, seq_no);

        // Get binary hash of the serialized lcl.
        std::string_view ledger_str_buf = msg::fbuf::flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
        const std::string lcl_hash = crypto::get_hash(ledger_str_buf);
        
        // Get binary hash of users and inputs.
        const std::string user_hash = crypto::get_hash(proposal.users);
        const std::string input_hash = crypto::get_hash(proposal.input_hashes);

        const std::string seq_no_str = std::to_string(seq_no);
        const std::string time_str = std::to_string(proposal.time);
        
        // Contruct binary string for data hash.
        std::string data;
        data.reserve(seq_no_str.size() + time_str.size() + (32 * 5));
        data.append(seq_no_str);
        data.append(time_str);
        data.append(proposal.state_hash.to_string_view());
        data.append(proposal.patch_hash.to_string_view());
        data.append(user_hash);
        data.append(input_hash);
        data.append(proposal.output_hash);

        // Get binary hash of data.
        const std::string data_hash = crypto::get_hash(data);

        // Construct ledger struct.
        // Hashes are stored as hex string;
        const sqlite::ledger ledger(
            seq_no,
            proposal.time,
            util::to_hex(lcl_hash),
            hash,
            util::to_hex(data_hash),
            util::to_hex(proposal.state_hash.to_string_view()),
            util::to_hex(proposal.patch_hash.to_string_view()),
            util::to_hex(user_hash),
            util::to_hex(input_hash),
            util::to_hex(proposal.output_hash));

        if (sqlite::insert_ledger_row(db, ledger) == -1)
        {
            sqlite3_close(db);
            return -1;
        }

        sqlite3_close(db);

        return 0;
    }

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash)
    {
        if (lcl == GENESIS_LEDGER)
        {
            seq_no = 0;
            hash = lcl.substr(2);
            return 0;
        }

        const size_t pos = lcl.find("-");
        if (pos == std::string::npos)
            return -1;

        if (util::stoull(lcl.substr(0, pos), seq_no) == -1)
            return -1;

        hash = lcl.substr(pos + 1);
        if (hash.size() != 64)
            return -1;

        return 0;
    }
} // namespace ledger::ledger_sample