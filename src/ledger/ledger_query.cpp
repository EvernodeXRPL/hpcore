#include "ledger_query.hpp"
#include "ledger_common.hpp"
#include "ledger.hpp"
#include "sqlite.hpp"

namespace ledger::query
{
#define RETURN_RESULT                                          \
    {                                                          \
        if (db != NULL && sqlite::close_db(&db) == -1)         \
            ret = -1;                                          \
        if (ledger::ledger_fs.stop_ro_session(query_id) == -1) \
            ret = -1;                                          \
        return ret;                                            \
    }

    /**
     * Get the ledger record by seq no.
     * @param seq_no Ledger sequence no. to search for.
     * @param ledger Ledger structure to populate.
     * @returns 1 if ledger found. 0 if ledger not found. -1 on failure.
    */
    int get_ledger_by_seq_no(const std::string &query_id, const uint64_t seq_no, ledger::ledger_record &ledger)
    {
        // Construct shard path based on provided ledger seq no.
        const uint64_t shard_seq_no = (seq_no - 1) / ledger::PRIMARY_SHARD_SIZE;
        const std::string shard_path = ledger::ledger_fs.physical_path(query_id, std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no)));
        if (ledger::ledger_fs.start_ro_session(query_id, false) == -1)
            return -1;

        sqlite3 *db = NULL;
        int ret = sqlite::open_db(shard_path + "/" + ledger::DATABASE, &db);
        if (ret != -1)
            ret = sqlite::get_ledger_by_seq_no(db, seq_no, ledger);

        RETURN_RESULT
    }
}