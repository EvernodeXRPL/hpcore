#include "ledger_query.hpp"
#include "ledger_common.hpp"
#include "ledger.hpp"
#include "sqlite.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"

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
            const seq_no_query &seq_q = std::get<seq_no_query>(q);
            const int seq_no_res = get_ledger_by_seq_no(ledger, seq_q, fs_sess_name);
            if (seq_no_res != -1)
            {
                if (seq_no_res == 1) // Ledger found.
                    records.push_back(query_result_record{std::move(ledger)});

                // Fill raw input/output data into results.
                if (fill_blob_data(records, seq_q.raw_inputs, seq_q.raw_outputs, fs_sess_name) != -1)
                    res = std::move(records);
            }
        }

        ledger::ledger_fs.stop_ro_session(fs_sess_name);
        return res;
    }

    /**
     * Fills in the raw input/output blob data to the specified ledger query result records.
     * @param records List of query results to fill in.
     * @param raw_inputs Whether raw inputs must be filled.
     * @param raw_outputs Whether raw outputs must be filled.
     * @param fs_sess_name The ledger hosting fs session name.
     */
    int fill_blob_data(std::vector<query_result_record> &records, const bool raw_inputs, const bool raw_outputs, const std::string &fs_sess_name)
    {
        // If blob data is not requested to be filled, the relevant field (inputs or outputs) in each result will contain NULL.
        // If blob data is requested to be filled, then the relevant field will contain the map of blobs or empty map.

        if (!raw_inputs && !raw_outputs)
            return 0; // Nothing to fill.

        for (query_result_record &r : records)
        {
            // Populate with empty map if inputs/outputs requested.
            if (raw_inputs)
                r.raw_inputs = blob_map();
            if (raw_outputs)
                r.raw_outputs = blob_map();

            if (r.ledger.seq_no == 0)
                return 0; // Nothing to fill for GENESIS ledger.

            const uint64_t shard_seq_no = (r.ledger.seq_no - 1) / ledger::BLOB_SHARD_SIZE;
            const std::string file_vpath = std::string(ledger::BLOB_DIR) + "/" + std::to_string(shard_seq_no) + "/" + util::to_hex(r.ledger.ledger_hash) + ".blob";
            const std::string file_path = ledger::ledger_fs.physical_path(fs_sess_name, file_vpath);
            std::string blob_msg;
            const int fd = open(file_path.data(), O_RDONLY);

            // If file does not exist, skip this leadger. (it means there are no input/output data for this leadger)
            if (fd == -1 && errno == ENOENT)
                continue;

            if (fd != -1 && util::read_from_fd(fd, blob_msg, util::HP_VERSION_HEADER_SIZE) > 0)
            {
                ledger_blob raw_data;
                if (msg::fbuf::ledgermsg::create_ledger_blob_from_msg(raw_data, blob_msg, raw_inputs, raw_outputs) != -1)
                {
                    if (raw_inputs)
                        raw_data.inputs.swap(*r.raw_inputs);

                    if (raw_outputs)
                        raw_data.outputs.swap(*r.raw_outputs);

                    close(fd);
                    continue;
                }
            }

            if (fd != -1)
                close(fd);

            // Reaching this point means loop has encountered an error.
            return -1;
        }

        return 0;
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
        const std::string db_vpath = std::string(ledger::PRIMARY_DIR) + "/" + std::to_string(shard_seq_no) + "/" + ledger::DATABASE;
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