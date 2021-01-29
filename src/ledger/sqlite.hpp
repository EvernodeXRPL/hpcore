#ifndef _LEDGER_SQLITE_
#define _LEDGER_SQLITE_

#include "../pchheader.hpp"

namespace ledger::sqlite
{
    /**
    * Define an enum and a string array for the column data types.
    * Any column data type that needs to be supportes should be added to both the 'COLUMN_DATA_TYPE' enum and the 'column_data_type' array in its respective order.
    */
    enum COLUMN_DATA_TYPE
    {
        INT,
        TEXT
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

        table_column_info(std::string_view name, const COLUMN_DATA_TYPE &column_type, const bool is_key = false, const bool is_null = false)
            : name(name), column_type(column_type), is_key(is_key), is_null(is_null)
        {
        }
    };

    /**
     * Struct for ledger feilds.
     * All the hashes are stored as hex strings.
    */
    struct ledger
    {
        uint64_t seq_no;
        uint64_t time;
        std::string ledger_hash_hex;
        std::string prev_ledger_hash_hex;
        std::string data_hash_hex;
        std::string state_hash_hex;
        std::string patch_hash_hex;
        std::string user_hash_hex;
        std::string input_hash_hex;
        std::string output_hash_hex;

        ledger(
            const uint64_t seq_no,
            const uint64_t time,
            std::string_view ledger_hash_hex,
            std::string_view prev_ledger_hash_hex,
            std::string_view data_hash_hex,
            std::string_view state_hash_hex,
            std::string_view patch_hash_hex,
            std::string_view user_hash_hex,
            std::string_view input_hash_hex,
            std::string_view output_hash_hex)
            : seq_no(seq_no),
              time(time),
              ledger_hash_hex(ledger_hash_hex),
              prev_ledger_hash_hex(prev_ledger_hash_hex),
              data_hash_hex(data_hash_hex),
              state_hash_hex(state_hash_hex),
              patch_hash_hex(patch_hash_hex),
              user_hash_hex(user_hash_hex),
              input_hash_hex(input_hash_hex),
              output_hash_hex(output_hash_hex)
        {
        }
    };

    // Generic methods.
    int open_db(std::string_view db_name, sqlite3 **db);

    int exec_sql(sqlite3 *db, std::string_view sql, int (*callback)(void *, int, char **, char **) = NULL, void *callback_first_arg = NULL);

    int create_table(sqlite3 *db, std::string_view table_name, const std::vector<table_column_info> &column_info);

    int insert_values(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, const std::vector<std::string> &value_strings);

    int insert_value(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, std::string_view value_string);

    bool is_table_exists(sqlite3 *db, std::string_view table_name);

    // Ledger specific methdods.
    int create_ledger_table(sqlite3 *db);

    int insert_ledger_row(sqlite3 *db, const ledger &ledger);

    bool is_ledger_table_exist(sqlite3 *db);
    
} // namespace ledger::sqlite

#endif