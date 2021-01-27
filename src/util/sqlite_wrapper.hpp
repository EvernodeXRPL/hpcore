#ifndef _SQLITE_WRAPPER_
#define _SQLITE_WRAPPER_

#include <iostream>
#include <string>
#include <vector>
#include <sqlite3.h>

namespace util::sqlite_wrapper
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

        table_column_info(const std::string name, const COLUMN_DATA_TYPE column_type, const bool is_key = false, const bool is_null = false)
            : name(std::move(name)), column_type(std::move(column_type)), is_key(std::move(is_key)), is_null(std::move(is_null))
        {
        }
    };

    /**
     * Struct for ledger feilds.
    */
    struct ledger
    {
        uint64_t seq_no;
        uint64_t time;
        std::string ledger_hash;
        std::string prev_ledger_hash;
        std::string data_hash;
        std::string state_hash;
        std::string patch_hash;
        std::string user_hash;
        std::string input_hash;
        std::string output_hash;

        ledger(
            const uint64_t seq_no,
            const uint64_t time,
            const std::string ledger_hash,
            const std::string prev_ledger_hash,
            const std::string data_hash,
            const std::string state_hash,
            const std::string patch_hash,
            const std::string user_hash,
            const std::string input_hash,
            const std::string output_hash)
            : seq_no(std::move(seq_no)),
            time(std::move(time)),
            ledger_hash(std::move(ledger_hash)),
            prev_ledger_hash(std::move(prev_ledger_hash)),
            data_hash(std::move(data_hash)),
            state_hash(std::move(state_hash)),
            patch_hash(std::move(patch_hash)),
            user_hash(std::move(user_hash)),
            input_hash(std::move(input_hash)),
            output_hash(std::move(output_hash))
        {
        }
    };

    int open_db(std::string_view db_name, sqlite3 **db);
    int exec_sql(sqlite3 *db, std::string_view sql, int (*callback)(void *, int, char **, char **), void *callback_first_arg);
    int create_table(sqlite3 *db, std::string_view table_name, const std::vector<table_column_info> &column_info);
    int insert_values(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, const std::vector<std::string> &value_strings);
    int create_ledger_table(sqlite3 *db);
    int insert_ledger_row(sqlite3 *db, const ledger &ledger);
} // namespace ledger::sqlite_wrapper

#endif 