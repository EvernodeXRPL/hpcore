#ifndef _HP_STATEFS_STATE_RESTORE_
#define _HP_STATEFS_STATE_RESTORE_

#include "../pchheader.hpp"
#include "hasher.hpp"
#include "state_common.hpp"

namespace statefs
{

class state_restore
{
private:
    state_dir_context ctx;
    std::unordered_set<std::string> created_dirs;
    void delete_new_files();
    int restore_touched_files();
    int read_block_index(std::vector<char> &buffer, std::string_view file);
    int restore_blocks(std::string_view file, const std::vector<char> &bindex);
    void rewind_checkpoints();

public:
    int rollback(hasher::B2H &root_hash);
};

} // namespace statefs

#endif
