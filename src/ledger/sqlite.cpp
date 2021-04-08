#include "sqlite.hpp"
#include "../util/h32.hpp"
#include "ledger_common.hpp"

namespace ledger::sqlite
{
    constexpr const char *LEDGER_TABLE = "ledger";
    constexpr const char *HP_VERSION_TABLE = "hp";
    constexpr const char *HP_VERSION_COLUMN = "hp_version";
    constexpr const char *COLUMN_DATA_TYPES[]{"INT", "TEXT", "BLOB"};
    constexpr const char *CREATE_TABLE = "CREATE TABLE IF NOT EXISTS ";
    constexpr const char *CREATE_INDEX = "CREATE INDEX ";
    constexpr const char *CREATE_UNIQUE_INDEX = "CREATE UNIQUE INDEX ";
    constexpr const char *INSERT_INTO = "INSERT INTO ";
    constexpr const char *PRIMARY_KEY = "PRIMARY KEY";
    constexpr const char *NOT_NULL = "NOT NULL";
    constexpr const char *VALUES = "VALUES";
    constexpr const char *SELECT_ALL = "SELECT * FROM ";
    constexpr const char *SQLITE_MASTER = "sqlite_master";
    constexpr const char *WHERE = " WHERE ";
    constexpr const char *AND = " AND ";
    constexpr const char *SELECT_LAST_LEDGER = "SELECT * FROM ledger ORDER BY seq_no DESC LIMIT 1";
    constexpr const char *SELECT_LEDGER_BY_SEQ_NO = "SELECT * FROM ledger WHERE seq_no=? LIMIT 1";
    constexpr const char *INSERT_INTO_LEDGER = "INSERT INTO ledger("
                                               "seq_no, time, ledger_hash, prev_ledger_hash, data_hash,"
                                               "state_hash, patch_hash, user_hash, input_hash, output_hash"
                                               ") VALUES(?,?,?,?,?,?,?,?,?,?)";

#define BIND_H32_BLOB(idx, field) (field.size() == sizeof(util::h32) && sqlite3_bind_blob(stmt, idx, field.data(), sizeof(util::h32), SQLITE_STATIC) == SQLITE_OK)
#define GET_H32_BLOB(idx) std::string((char *)sqlite3_column_blob(stmt, idx), sizeof(util::h32))

    /**
     * Opens a connection to a given databse and give the db pointer.
     * @param db_name Database name to be connected.
     * @param db Pointer to the db pointer which is to be connected and pointed.
     * @returns returns 0 on success, or -1 on error.
    */
    int open_db(std::string_view db_name, sqlite3 **db)
    {
        int ret;
        if ((ret = sqlite3_open(db_name.data(), db)) != SQLITE_OK)
        {
            *db = NULL;
            LOG_ERROR << "Can't open database: " << ret << ", " << sqlite3_errmsg(*db);
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
    int exec_sql(sqlite3 *db, std::string_view sql, int (*callback)(void *, int, char **, char **), void *callback_first_arg)
    {
        char *err_msg;
        if (sqlite3_exec(db, sql.data(), callback, (callback != NULL ? (void *)callback_first_arg : NULL), &err_msg) != SQLITE_OK)
        {
            LOG_ERROR << "SQL error occured: " << err_msg;
            sqlite3_free(err_msg);
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
    int create_table(sqlite3 *db, std::string_view table_name, const std::vector<table_column_info> &column_info)
    {
        std::string sql;
        sql.append(CREATE_TABLE).append(table_name).append(" (");

        for (auto itr = column_info.begin(); itr != column_info.end(); ++itr)
        {
            sql.append(itr->name);
            sql.append(" ");
            sql.append(COLUMN_DATA_TYPES[itr->column_type]);

            if (itr->is_key)
            {
                sql.append(" ");
                sql.append(PRIMARY_KEY);
            }

            if (!itr->is_null)
            {
                sql.append(" ");
                sql.append(NOT_NULL);
            }

            if (itr != column_info.end() - 1)
                sql.append(",");
        }
        sql.append(")");

        const int ret = exec_sql(db, sql);
        if (ret == -1)
            LOG_ERROR << "Error when creating sqlite table " << table_name;

        return ret;
    }

    int create_index(sqlite3 *db, std::string_view table_name, std::string_view column_name, const bool is_unique)
    {
        std::string sql;
        sql.append(is_unique ? CREATE_UNIQUE_INDEX : CREATE_INDEX)
            .append("idx_")
            .append(table_name)
            .append("_")
            .append(column_name)
            .append(" ON ")
            .append(table_name)
            .append("(")
            .append(column_name)
            .append(")");

        const int ret = exec_sql(db, sql);
        if (ret == -1)
            LOG_ERROR << "Error when creating sqlite index '" << column_name << "' in table " << table_name;

        return ret;
    }

    /**
     * Inserts mulitple rows to a table.
     * @param db Pointer to the db.
     * @param table_name Table name to be populated.
     * @param column_names_string Comma seperated string of colums (eg: "col_1,col_2,...").
     * @param value_strings Vector of comma seperated values (wrap in single quotes for TEXT type) (eg: ["r1val1,'r1val2',...", "r2val1,'r2val2',..."]).
     * @returns returns 0 on success, or -1 on error.
    */
    int insert_rows(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, const std::vector<std::string> &value_strings)
    {
        std::string sql;

        sql.append(INSERT_INTO);
        sql.append(table_name);
        sql.append("(");
        sql.append(column_names_string);
        sql.append(") ");
        sql.append(VALUES);

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
     * Inserts a row to a table.
     * @param db Pointer to the db.
     * @param table_name Table name to be populated.
     * @param column_names_string Comma seperated string of colums (eg: "col_1,col_2,...").
     * @param value_string comma seperated values as per column order (wrap in single quotes for TEXT type) (eg: "r1val1,'r1val2',...").
     * @returns returns 0 on success, or -1 on error.
    */
    int insert_row(sqlite3 *db, std::string_view table_name, std::string_view column_names_string, std::string_view value_string)
    {
        std::string sql;
        // Reserving the space for the query before construction.
        sql.reserve(sizeof(INSERT_INTO) + table_name.size() + column_names_string.size() + sizeof(VALUES) + value_string.size() + 5);

        sql.append(INSERT_INTO);
        sql.append(table_name);
        sql.append("(");
        sql.append(column_names_string);
        sql.append(") ");
        sql.append(VALUES);
        sql.append("(");
        sql.append(value_string);
        sql.append(")");

        /* Execute SQL statement */
        return exec_sql(db, sql);
    }

    /**
     * Checks whether table exist in the database.
     * @param db Pointer to the db.
     * @param table_name Table name to be checked.
     * @returns returns true is exist, otherwise false.
    */
    bool is_table_exists(sqlite3 *db, std::string_view table_name)
    {
        std::string sql;
        // Reserving the space for the query before construction.
        sql.reserve(sizeof(SELECT_ALL) + sizeof(SQLITE_MASTER) + sizeof(WHERE) + sizeof(AND) + table_name.size() + 19);

        sql.append(SELECT_ALL);
        sql.append(SQLITE_MASTER);
        sql.append(WHERE);
        sql.append("type='table'");
        sql.append(AND);
        sql.append("name='");
        sql.append(table_name);
        sql.append("'");

        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, sql.data(), -1, &stmt, 0) == SQLITE_OK &&
            stmt != NULL && sqlite3_step(stmt) == SQLITE_ROW)
        {
            // Finalize and distroys the statement.
            sqlite3_finalize(stmt);
            return true;
        }

        // Finalize and distroys the statement.
        sqlite3_finalize(stmt);
        return false;
    }

    /**
     * Closes a connection to a given databse.
     * @param db Pointer to the db.
     * @returns returns 0 on success, or -1 on error.
    */
    int close_db(sqlite3 **db)
    {
        if (sqlite3_close(*db) != SQLITE_OK)
        {
            LOG_ERROR << "Can't close database: " << sqlite3_errmsg(*db);
            return -1;
        }

        *db = NULL;
        return 0;
    }

    /**
     * Creates a table for ledger records.
     * @param db Pointer to the db.
     * @returns returns 0 on success, or -1 on error.
    */
    int create_ledger_table(sqlite3 *db)
    {
        const std::vector<table_column_info> column_info{
            table_column_info("seq_no", COLUMN_DATA_TYPE::INT, true),
            table_column_info("time", COLUMN_DATA_TYPE::INT),
            table_column_info("ledger_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("prev_ledger_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("data_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("state_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("patch_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("user_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("input_hash", COLUMN_DATA_TYPE::BLOB),
            table_column_info("output_hash", COLUMN_DATA_TYPE::BLOB)};

        if (create_table(db, LEDGER_TABLE, column_info) == -1 ||
            create_index(db, LEDGER_TABLE, "time", true) == -1 ||
            create_index(db, LEDGER_TABLE, "ledger_hash", true) == -1)
            return -1;

        return 0;
    }

    /**
     * Create and update the hp table from the hp version when creating a new shard.
     * @param db Pointer to the db.
     * @param version Hp version.
     * @returns returns 0 on success, or -1 on error.
     * 
    */
    int create_hp_version_table_and_update(sqlite3 *db, std::string_view version)
    {
        const std::vector<table_column_info> column_info{
            table_column_info(HP_VERSION_COLUMN, COLUMN_DATA_TYPE::TEXT)};

        if (create_table(db, HP_VERSION_TABLE, column_info) == -1)
            return -1;

        const std::string value_string = "\"" + std::string(version) + "\"";
        if (insert_row(db, HP_VERSION_TABLE, HP_VERSION_COLUMN, value_string) == -1)
            return -1;

        return 0;
    }

    /**
     * Inserts a ledger record.
     * @param db Pointer to the db.
     * @param ledger Ledger struct to be inserted.
     * @returns returns 0 on success, or -1 on error.
    */
    int insert_ledger_row(sqlite3 *db, const ledger::ledger_record &ledger)
    {
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, INSERT_INTO_LEDGER, -1, &stmt, 0) == SQLITE_OK && stmt != NULL &&
            sqlite3_bind_int64(stmt, 1, ledger.seq_no) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 2, ledger.timestamp) == SQLITE_OK &&
            BIND_H32_BLOB(3, ledger.ledger_hash) &&
            BIND_H32_BLOB(4, ledger.prev_ledger_hash) &&
            BIND_H32_BLOB(5, ledger.data_hash) &&
            BIND_H32_BLOB(6, ledger.state_hash) &&
            BIND_H32_BLOB(7, ledger.config_hash) &&
            BIND_H32_BLOB(8, ledger.user_hash) &&
            BIND_H32_BLOB(9, ledger.input_hash) &&
            BIND_H32_BLOB(10, ledger.output_hash) &&
            sqlite3_step(stmt) == SQLITE_DONE)
        {
            sqlite3_finalize(stmt);
            return 0;
        }

        sqlite3_finalize(stmt);
        return -1;
    }

    /**
     * Checks whether ledger table exist.
     * @param db Pointer to the db.
     * @returns returns true is exist, otherwise false.
    */
    bool is_ledger_table_exist(sqlite3 *db)
    {
        return is_table_exists(db, LEDGER_TABLE);
    }

    /**
     * Get the last ledger record of the given db.
     * @param db Pointer to the db.
     * @param ledger Ledger structure to populate.
     * @returns 0 on success. -1 on failure.
    */
    int get_last_ledger(sqlite3 *db, ledger::ledger_record &ledger)
    {
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, SELECT_LAST_LEDGER, -1, &stmt, 0) == SQLITE_OK && stmt != NULL &&
            sqlite3_step(stmt) == SQLITE_ROW)
        {
            populate_ledger_from_sql_record(ledger, stmt);
            sqlite3_finalize(stmt);
            return 0;
        }

        LOG_ERROR << "Error when querying last ledger from db.";
        sqlite3_finalize(stmt);
        return -1;
    }

    /**
     * Get the ledger record by seq no.
     * @param db Pointer to the db.
     * @param seq_no Ledger sequence no. to search for.
     * @param ledger Ledger structure to populate.
     * @returns 1 if ledger found. 0 if ledger not found. -1 on failure.
    */
    int get_ledger_by_seq_no(sqlite3 *db, const uint64_t seq_no, ledger::ledger_record &ledger)
    {
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, SELECT_LEDGER_BY_SEQ_NO, -1, &stmt, 0) == SQLITE_OK && stmt != NULL &&
            sqlite3_bind_int64(stmt, 1, seq_no) == SQLITE_OK)
        {
            const int result = sqlite3_step(stmt);
            if (result == SQLITE_ROW)
            {
                populate_ledger_from_sql_record(ledger, stmt);
                sqlite3_finalize(stmt);
                return 1; // Ledger found.
            }
            else if (result == SQLITE_DONE)
            {
                sqlite3_finalize(stmt);
                return 0; // Not found.
            }
        }

        LOG_ERROR << "Error when querying ledger by seq no. from db.";
        sqlite3_finalize(stmt);
        return -1;
    }

    void populate_ledger_from_sql_record(ledger::ledger_record &ledger, sqlite3_stmt *stmt)
    {
        ledger.seq_no = sqlite3_column_int64(stmt, 0);
        ledger.timestamp = sqlite3_column_int64(stmt, 1);
        ledger.ledger_hash = GET_H32_BLOB(2);
        ledger.prev_ledger_hash = GET_H32_BLOB(3);
        ledger.data_hash = GET_H32_BLOB(4);
        ledger.state_hash = GET_H32_BLOB(5);
        ledger.config_hash = GET_H32_BLOB(6);
        ledger.user_hash = GET_H32_BLOB(7);
        ledger.input_hash = GET_H32_BLOB(8);
        ledger.output_hash = GET_H32_BLOB(9);
    }

} // namespace ledger::sqlite
