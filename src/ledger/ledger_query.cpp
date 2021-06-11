#include "ledger_query.hpp"
#include "ledger_common.hpp"
#include "ledger.hpp"
#include "sqlite.hpp"
#include "../conf.hpp"
#include "../util/version.hpp"

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

        std::vector<ledger::ledger_record> ledgers;

        if (q.index() == 0) // Filter by seq no.
        {
            ledger_record ledger;
            const seq_no_query &seq_q = std::get<seq_no_query>(q);
            const int seq_no_res = get_ledger_by_seq_no(ledger, seq_q, fs_sess_name);
            if (seq_no_res != -1)
            {
                if (seq_no_res == 1) // Ledger found.
                    ledgers.push_back(std::move(ledger));

                // Fill raw data if required.
                if (seq_q.inputs || seq_q.outputs)
                {
                    // Do not return other users' blobs if consensus is private.
                    const std::string filter_user = conf::cfg.contract.is_consensus_public ? "" : std::string(user_pubkey);

                    for (ledger_record &ledger : ledgers)
                    {
                        if (seq_q.inputs)
                            ledger.inputs = std::vector<ledger::ledger_user_input>();
                        if (seq_q.outputs)
                            ledger.outputs = std::vector<ledger::ledger_user_output>();

                        // No need to actually query raw data for genesis ledger.
                        if (seq_q.seq_no == 0 || get_ledger_raw_data(ledger, filter_user, fs_sess_name) != -1)
                            res = ledgers;
                    }
                }
                else
                {
                    res = ledgers;
                }
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
        const uint64_t shard_seq_no = SHARD_SEQ(q.seq_no, ledger::PRIMARY_SHARD_SIZE);
        const std::string db_vpath = std::string(ledger::PRIMARY_DIR) + "/" + std::to_string(shard_seq_no) + "/" + ledger::PRIMARY_DB;
        const std::string db_path = ledger::ledger_fs.physical_path(fs_sess_name, db_vpath);

        if (!util::is_file_exists(db_path))
            return 0; // Not found.

        sqlite3 *db = NULL;
        if (sqlite::open_db(db_path, &db) == -1)
            return -1;

        const int sql_res = sqlite::get_ledger_by_seq_no(db, q.seq_no, ledger);
        sqlite::close_db(&db);
        return sql_res;
    }

    /**
     * Retrieve user inputs and outputs by ledger seq no. If consensus is private, this only fills blobs of the requesting user.
     * @param ledger Ledger record to populate with inputs and outputs.
     * @param user_pubkey Binary user pubkey. If not empty, include raw data only for this user.
     * @param fs_sess_name The ledger hosting fs session name.
     * @returns 0 on success. -1 on failure.
     */
    int get_ledger_raw_data(ledger_record &ledger, std::string_view user_pubkey, const std::string &fs_sess_name)
    {
        // If both inputs and outputs collections are null, don't proceed.
        if (!ledger.inputs && !ledger.outputs)
            return 0;

        const uint64_t shard_seq_no = SHARD_SEQ(ledger.seq_no, ledger::RAW_SHARD_SIZE);
        const std::string shard_path = ledger::ledger_fs.physical_path(fs_sess_name, std::string(ledger::RAW_DIR) + "/" + std::to_string(shard_seq_no) + "/");
        const std::string db_path = shard_path + RAW_DB;

        if (!util::is_file_exists(db_path))
            return 0; // Not found.

        sqlite3 *db = NULL;
        if (sqlite::open_db(db_path, &db) == -1)
            return -1;

        if ((ledger.inputs && get_ledger_inputs(db, *ledger.inputs, ledger.seq_no, shard_path, user_pubkey, fs_sess_name) == -1) ||
            (ledger.outputs && get_ledger_outputs(db, *ledger.outputs, ledger.seq_no, shard_path, user_pubkey, fs_sess_name) == -1))
        {
            sqlite::close_db(&db);
            return -1;
        }

        sqlite::close_db(&db);
        return 0;
    }

    /**
     * Retrieve user inputs by ledger seq no. If consensus is private, this only fills blobs of the requesting user.
     * @param db Sqlite db connection for raw data db.
     * @param inputs User input collection to populate.
     * @param seq_no Ledger seq no. to query.
     * @param shard_path The shard physical path.
     * @param user_pubkey Binary user pubkey. If not empty, include raw data only for this user.
     * @param fs_sess_name The ledger hosting fs session name.
     * @returns 0 on success. -1 on failure.
     */
    int get_ledger_inputs(sqlite3 *db, std::vector<ledger_user_input> &inputs, const uint64_t seq_no, const std::string &shard_path, std::string_view user_pubkey, const std::string &fs_sess_name)
    {
        if (sqlite::get_user_inputs_by_seq_no(db, seq_no, inputs) == -1)
            return -1;

        if (inputs.empty())
            return 0;

        const std::string blob_file = shard_path + RAW_INPUTS_FILE;
        const int fd = open(blob_file.data(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error in query when opening " << blob_file;
            return -1;
        }

        for (ledger_user_input &inp : inputs)
        {
            // Apply user filter.
            if (!user_pubkey.empty() && inp.pubkey != user_pubkey)
                continue;

            inp.blob.resize(inp.blob_size);
            if (util::read_from_fd(fd, inp.blob.data(), inp.blob_size, inp.blob_offset, blob_file) == -1)
            {
                close(fd);
                return -1;
            }
        }

        close(fd);
        return 0;
    }

    /**
     * Retrieve user outputs by ledger seq no. If consensus is private, this only fills blobs of the requesting user.
     * @param db Sqlite db connection for raw data db.
     * @param outputs User output collection to populate.
     * @param seq_no Ledger seq no. to query.
     * @param shard_path The shard physical path.
     * @param user_pubkey Binary user pubkey. If not empty, include raw data only for this user.
     * @param fs_sess_name The ledger hosting fs session name.
     * @returns 0 on success. -1 on failure.
     */
    int get_ledger_outputs(sqlite3 *db, std::vector<ledger_user_output> &outputs, const uint64_t seq_no, const std::string &shard_path, std::string_view user_pubkey, const std::string &fs_sess_name)
    {
        if (sqlite::get_user_outputs_by_seq_no(db, seq_no, outputs) == -1)
            return -1;

        if (outputs.empty())
            return 0;

        const std::string blob_file = shard_path + RAW_OUTPUTS_FILE;
        const int fd = open(blob_file.data(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error in query when opening " << blob_file;
            return -1;
        }

        // Loop through each user's blob groups.
        for (ledger_user_output &user : outputs)
        {
            // Apply user filter.
            if (!user_pubkey.empty() && user.pubkey != user_pubkey)
                continue;

            // Output blobs for each user are grouped. Group header contains all individual blob offsets and sizes
            // for that user, followed by actual blobs.

            // Read the entire header.
            const off_t header_pos = user.blob_offset;
            std::vector<uint8_t> header(user.blob_count * (sizeof(off_t) + sizeof(size_t)));
            if (util::read_from_fd(fd, header.data(), header.size(), header_pos, blob_file) == -1)
            {
                close(fd);
                return -1;
            }

            for (size_t i = 0; i < user.blob_count; i++)
            {
                // Position inside the header which contains the offset of the individual output blob.
                const off_t header_read_pos = i * (sizeof(off_t) + sizeof(size_t));
                const uint64_t offset = util::uint64_from_bytes(header.data() + header_read_pos);
                const size_t size = util::uint64_from_bytes(header.data() + header_read_pos + sizeof(size_t));

                // Read the output blob content.
                std::string output;
                output.resize(size);
                if (util::read_from_fd(fd, output.data(), output.size(), offset, blob_file) == -1)
                {
                    close(fd);
                    return -1;
                }
                user.outputs.push_back(std::move(output));
            }
        }

        close(fd);
        return 0;
    }

    /**
     * Loads inputs and connected users from the specified ledger.
     */
    int get_input_users_from_ledger(const uint64_t seq_no, std::vector<std::string> &users, std::vector<ledger_user_input> &inputs)
    {
        const char *session_name = "input_users";
        if (ledger_fs.start_ro_session(session_name, false) == -1)
            return -1;

        const uint64_t shard_seq_no = SHARD_SEQ(seq_no, ledger::RAW_SHARD_SIZE);
        const std::string shard_path = ledger::ledger_fs.physical_path(session_name, std::string(ledger::RAW_DIR) + "/" + std::to_string(shard_seq_no) + "/");
        const std::string db_path = shard_path + RAW_DB;

        sqlite3 *db = NULL;
        if (sqlite::open_db(db_path, &db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database for input_users, shard: " << shard_seq_no;
            ledger_fs.stop_ro_session(session_name);
            return -1;
        }

        if (sqlite::get_users_by_seq_no(db, seq_no, users) == -1 ||
            sqlite::get_user_inputs_by_seq_no(db, seq_no, inputs) == -1)
        {
            LOG_ERROR << errno << ": Error querying ledger input_users, seq_no: " << seq_no;
            sqlite::close_db(&db);
            ledger_fs.stop_ro_session(session_name);
            return -1;
        }

        sqlite::close_db(&db);
        ledger_fs.stop_ro_session(session_name);
        return 0;
    }

    int get_input_by_hash(const uint64_t last_primary_shard_seq_no, std::string_view hash, std::optional<ledger::ledger_user_input> &input)
    {
        const char *session_name = "input_by_hash";
        if (ledger_fs.start_ro_session(session_name, false) == -1)
            return -1;

        // Search all the shards starting with last shard for the input hash.
        for (uint64_t shard_seq_no = last_primary_shard_seq_no; shard_seq_no >= 0 && !input; shard_seq_no--)
        {
            const std::string shard_path = ledger::ledger_fs.physical_path(session_name, std::string(ledger::RAW_DIR) + "/" + std::to_string(shard_seq_no) + "/");
            const std::string db_path = shard_path + RAW_DB;

            if (!util::is_file_exists(db_path))
                return 0; // Not found.

            sqlite3 *db = NULL;
            if (sqlite::open_db(db_path, &db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database to find input hash, shard: " << shard_seq_no;
                ledger_fs.stop_ro_session(session_name);
                return -1;
            }

            if (sqlite::get_user_input_by_hash(db, hash, input) == -1)
            {
                LOG_ERROR << errno << ": Error finding input hash in shard " << shard_seq_no;
                sqlite::close_db(&db);
                ledger_fs.stop_ro_session(session_name);
                return -1;
            }

            sqlite::close_db(&db);
        }

        ledger_fs.stop_ro_session(session_name);
        return 0;
    }
}