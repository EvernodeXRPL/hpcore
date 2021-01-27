#include "../../src/util/sqlite_wrapper.hpp"
#include <unistd.h>

namespace sqlite_wrapper =  util::sqlite_wrapper;

int main()
{
    sqlite3 *db;

    if (sqlite_wrapper::open_db("ledger.db", &db) == -1)
    {
        sqlite3_close(db);
        return -1;
    }
    else
        std::cout << "DB openned successfully.\n";

    if (sqlite_wrapper::create_ledger_table(db) == -1)
    {
        sqlite3_close(db);
        return -1;
    }
    else
        std::cout << "Table created successfully.\n";

    if (sqlite_wrapper::insert_ledger_row(db, sqlite_wrapper::ledger(1, 1, "test", "test", "test", "test", "test", "test", "test", "test")) == -1)
    {
        sqlite3_close(db);
        return -1;
    }
    else
        std::cout << "Record added successfully.\n";

    sqlite3_close(db);

    return 0;
}