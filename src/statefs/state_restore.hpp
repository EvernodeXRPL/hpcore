#ifndef _STATEFS_STATE_RESTORE_
#define _STATEFS_STATE_RESTORE_

#include <string>
#include <unordered_set>
#include <vector>
#include "state_common.hpp"

namespace statefs
{

class state_restore
{
private:
    statedir_context ctx;
    std::unordered_set<std::string> created_dirs;
    void delete_newfiles();
    int restore_touchedfiles();
    int read_blockindex(std::vector<char> &buffer, std::string_view file);
    int restore_blocks(std::string_view file, const std::vector<char> &bindex);
    void rewind_checkpoints();

public:
    int rollback();
};

} // namespace statefs

#endif
