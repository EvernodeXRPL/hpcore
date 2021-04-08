#ifndef _LEDGER_SQLITE_
#define _LEDGER_SQLITE_

#include "../pchheader.hpp"
#include "ledger_common.hpp"

namespace ledger::sqlite
{
    /**
    * Define an enum and a string array for the column data types.
    * Any column data type that needs to be supportes should be added to both the 'COLUMN_DATA_TYPE' enum and the 'column_data_type' array in its respective order.
    */
    enum COLUMN_DATA_TYPE
    {
        INT,
        TEXT,
        BLOB
    };

    /**
     * Struct of table column information.
     * {
     *  string name   Name of the column.
     *  column_type   Data type of the column.
     *  is_key        Whether column is a key.
     *  is_null       Whether column is nullable.
     * }
    */
    struct table_column_info
    {
        std::string name;
        COLUMN_DATA_TYPE column_type;
        bool is_key;
        bool is_null;

        table_column_info(std::string_view name, const COLUMN_DATA_TYPE &column_type, const bool is_key = false, const bool is_null = true)
            : name(name), column_type(column_type), is_key(is_key), is_null(is_null)
        {
        }
    };

    // Generic methods.
    int open_db(std::string_view db_name, sqlite3 **db);

    int exec_sql(sqlite3 *db, std::string_view sql, int (*callback)(void *, int, char **, char **) = NULL, void *callback_first_arg = NULL);

    int create_table(sqlite3 *db, std::string_view table_name, const std::vector<table_column_info> &column_info);

    int create_index(sqlite3 *db, std::string_view table_name, std::string_view column_names, const bool is_unique);

    int insert_rows(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, const std::vector<std::string> &value_strings);

    int insert_row(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, std::string_view value_string);

    bool is_table_exists(sqlite3 *db, std::string_view table_name);

    int close_db(sqlite3 **db);

    // Ledger specific methdods.
    int initialize_ledger_db(sqlite3 *db);

    int initialize_ledger_raw_db(sqlite3 *db);

    int create_hp_table(sqlite3 *db, std::string_view version);

    int insert_ledger_row(sqlite3 *db, const ledger::ledger_record &ledger);

    int insert_user_record(sqlite3 *db, const uint64_t ledger_seq_no, std::string_view pubkey);

    int insert_user_input_record(sqlite3 *db, const uint64_t ledger_seq_no, std::string_view user_pubkey,
                                 std::string_view hash, std::string_view nonce, const uint64_t blob_offset, const uint64_t blob_size);

    int insert_user_output_record(sqlite3 *db, const uint64_t ledger_seq_no, std::string_view user_pubkey,
                                  std::string_view hash, const uint64_t blob_offset, const uint64_t blob_size);

    int get_last_ledger(sqlite3 *db, ledger::ledger_record &ledger);

    int get_ledger_by_seq_no(sqlite3 *db, const uint64_t seq_no, ledger::ledger_record &ledger);

    void populate_ledger_from_sql_record(ledger::ledger_record &ledger, sqlite3_stmt *stmt);

} // namespace ledger::sqlite

#endif