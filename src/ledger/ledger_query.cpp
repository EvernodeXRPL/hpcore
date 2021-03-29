#include "ledger_query.hpp"
#include "ledger_common.hpp"
#include "ledger.hpp"
#include "sqlite.hpp"

namespace ledger::query
{
    constexpr const char *ERROR_EXEC_FAILURE = "exec_failure";

    /**
     * Executes the specified ledger query and returns the result.
     * @param user_pubkey Binary pubkey of the user executing the query.
     * @param q The query information.
     * @returns The query result.
     */
    const query_result execute(std::string_view user_pubkey, const query_request &q)
    {
        query_result res = ERROR_EXEC_FAILURE;

        // Query the ledger with a ledger fs readonly session.

        // Allocate unique readonly session name prefixed with user pubkey.
        // There will always only be one query execution per user because each user session
        // processes messages sequentially.
        const std::string fs_sess_name = "lqr_" + util::to_hex(user_pubkey);

        if (ledger::ledger_fs.start_ro_session(fs_sess_name, false) == -1)
            return res;

        std::vector<query_result_record> records;

        if (q.index() == 0) // Filter by seq no.
        {
            ledger_record ledger;
            const int seq_no_res = get_ledger_by_seq_no(ledger, std::get<seq_no_query>(q), fs_sess_name);
            if (seq_no_res != -1)
            {
                if (seq_no_res == 1) // Ledger found.
                    records.push_back(query_result_record{std::move(ledger)});
                res = std::move(records);
            }
        }

        ledger::ledger_fs.stop_ro_session(fs_sess_name);
        return res;
    }

    /**
     * Get the ledger record by seq no.
     * @param ledger Ledger structure to populate (if match found)).
     * @param q The seq no query information.
     * @param fs_sess_name The ledger hosting fs session name.
     * @returns 1 if ledger found. 0 if ledger not found. -1 on failure.
    */
    int get_ledger_by_seq_no(ledger_record &ledger, const seq_no_query &q, const std::string &fs_sess_name)
    {
        // If seq no. is 0, return GENESIS ledger.
        if (q.seq_no == 0)
        {
            ledger = ledger::genesis;
            return 1;
        }

        // Construct shard path based on provided ledger seq no.
        const uint64_t shard_seq_no = (q.seq_no - 1) / ledger::PRIMARY_SHARD_SIZE;
        const std::string db_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no)).append("/").append(ledger::DATABASE);
        const std::string dbpath = ledger::ledger_fs.physical_path(fs_sess_name, db_vpath);

        if (!util::is_file_exists(dbpath))
            return 0; // Not found.

        query_result_record result;

        sqlite3 *db = NULL;
        if (sqlite::open_db(dbpath, &db) == -1)
            return -1;

        const int sql_res = sqlite::get_ledger_by_seq_no(db, q.seq_no, ledger);
        sqlite::close_db(&db);
        return sql_res;
    }
}