#include "sqlite_wrapper.hpp"

namespace util::sqlite_wrapper
{
    const std::string LEDGER_TABLE = "ledger";
    const std::string LEDGER_COLUMNS = "seq_no, time, ledger_hash, prev_ledger_hash, data_hash, state_hash, patch_hash, user_hash, input_hash, output_hash";
    const std::string COLUMN_DATA_TYPES[]{"INT", "TEXT"};
    const std::string CREATE_TABLE = "CREATE TABLE ";
    const std::string INSERT_INTO = "INSERT INTO ";
    const std::string PRIMARY_KEY = "PRIMARY KEY";
    const std::string NOT_NULL = "NOT NULL";
    const std::string VALUES = "VALUES";
    const std::string SELECT_ALL = "SELECT * FROM ";

    /**
     * Opens a connection to a given databse and give the db pointer.
     * @param db_name Database name to be connected.
     * @param db Pointer to the db pointer which is to be connected and ponted.
     * @returns returns 0 on success, or -1 on error.
    */
    int open_db(std::string_view db_name, sqlite3 **db)
    {
        if (sqlite3_open(db_name.data(), db) != SQLITE_OK)
        {
            std::cout << "Can't open database: " << sqlite3_errmsg(*db) << "\n";
            return -1;
        }
        return 0;
    }

    /**
     * Executes given sql query.
     * @param db Pointer to the db.
     * @param sql Sql query to be executed.
     * @param callback Callback funcion which is called for each result row.
     * @param callback_first_arg First data argumat to be parced to the callback (void pointer).
     * @returns returns 0 on success, or -1 on error.
    */
    int exec_sql(sqlite3 *db, std::string_view sql, int (*callback)(void *, int, char **, char **) = NULL, void *callback_first_arg = NULL)
    {
        char *zErrMsg;
        if (sqlite3_exec(db, sql.data(), callback, (callback != NULL ? (void *)callback_first_arg : NULL), &zErrMsg) != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            return -1;
        }
        return 0;
    }

    /**
     * Create a table with given table info.
     * @param db Pointer to the db.
     * @param table_name Table name to be created.
     * @param column_info Column info of the table.
     * @returns returns 0 on success, or -1 on error.
    */
    int create_table(sqlite3 *db, std::string_view table_name, const std::vector<util::sqlite_wrapper::table_column_info> &column_info)
    {
        std::string sql;
        sql.append(CREATE_TABLE);
        sql.append(table_name);
        sql.append(" (");

        for (auto itr = column_info.begin(); itr != column_info.end(); ++itr)
        {
            sql.append(itr->name + " " + COLUMN_DATA_TYPES[itr->column_type]);

            if (itr->is_key)
                sql.append(" " + PRIMARY_KEY);

            if (!itr->is_null)
                sql.append(" " + NOT_NULL);

            if (itr != column_info.end() - 1)
                sql.append(",");
        }
        sql.append(")");

        /* Execute SQL statement */
        return exec_sql(db, sql);
    }

    /**
     * Insert values to a table.
     * @param db Pointer to the db.
     * @param table_name Table name to be populated.
     * @param column_names_string Comma seperated string of colums (eg: "col_1,col_2,...").
     * @param value_strings Vector of comma seperated values (wrap in single quotes for TEXT type) (eg: ["r1val1,'r1val2',...", "r2val1,'r2val2',..."]).
     * @returns returns 0 on success, or -1 on error.
    */
    int insert_values(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, const std::vector<std::string> &value_strings)
    {
        std::string sql;

        sql.append(INSERT_INTO);
        sql.append(table_name);
        sql.append("(");
        sql.append(column_names_string);
        sql.append(")");
        sql.append(" " + VALUES);

        for (auto itr = value_strings.begin(); itr != value_strings.end(); ++itr)
        {
            sql.append("(");
            sql.append(*itr);
            sql.append(")");

            if (itr != value_strings.end() - 1)
                sql.append(",");
        }

        /* Execute SQL statement */
        return exec_sql(db, sql);
    }

    /**
     * Insert a value row to a table.
     * @param db Pointer to the db.
     * @param table_name Table name to be populated.
     * @param column_names_string Comma seperated string of colums (eg: "col_1,col_2,...").
     * @param value_strings Vector of comma seperated values (wrap in single quotes for TEXT type) (eg: ["r1val1,'r1val2',...", "r2val1,'r2val2',..."]).
     * @returns returns 0 on success, or -1 on error.
    */
    int insert_value(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, std::string_view value_string)
    {
        std::string sql;

        sql.append(INSERT_INTO);
        sql.append(table_name);
        sql.append("(");
        sql.append(column_names_string);
        sql.append(")");
        sql.append(" " + VALUES);
        sql.append("(");
        sql.append(value_string);
        sql.append(")");

        /* Execute SQL statement */
        return exec_sql(db, sql);
    }

    int create_ledger_table(sqlite3 *db)
    {
        std::vector< util::sqlite_wrapper::table_column_info> column_info{
             util::sqlite_wrapper::table_column_info("seq_no",  util::sqlite_wrapper::COLUMN_DATA_TYPE::INT, true),
             util::sqlite_wrapper::table_column_info("time",  util::sqlite_wrapper::COLUMN_DATA_TYPE::INT),
             util::sqlite_wrapper::table_column_info("ledger_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("prev_ledger_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("data_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("state_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("patch_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("user_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("input_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT),
             util::sqlite_wrapper::table_column_info("output_hash",  util::sqlite_wrapper::COLUMN_DATA_TYPE::TEXT)};

        if ( util::sqlite_wrapper::create_table(db, LEDGER_TABLE, column_info) == -1)
            return -1;

        return 0;
    }

    std::string add_quote(std::string value)
    {
        return "'" + value + "'";
    }

    int insert_ledger_row(sqlite3 *db, const util::sqlite_wrapper::ledger &ledger)
    {
        const std::string ledger_seq_no_str = std::to_string(ledger.seq_no);
        const std::string ledger_time_str = std::to_string(ledger.time);

        std::string value_string;
        value_string.reserve(ledger_seq_no_str.length() + ledger_time_str.length() + (64*8) + 9);

        value_string.append(ledger_seq_no_str + ",");
        value_string.append(ledger_time_str + ",");
        value_string.append(add_quote(ledger.ledger_hash) + ",");
        value_string.append(add_quote(ledger.prev_ledger_hash) + ",");
        value_string.append(add_quote(ledger.data_hash) + ",");
        value_string.append(add_quote(ledger.state_hash) + ",");
        value_string.append(add_quote(ledger.patch_hash) + ",");
        value_string.append(add_quote(ledger.user_hash) + ",");
        value_string.append(add_quote(ledger.input_hash) + ",");
        value_string.append(add_quote(ledger.output_hash));

        if ( insert_value(db, LEDGER_TABLE, LEDGER_COLUMNS, value_string) == -1)
            return -1;

        return 0;
    }
} // namespace ledger::sqlite_wrapper