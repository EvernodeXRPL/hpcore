#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"

namespace hpfs
{
    int init();
    void deinit();
    int start_hpfs_process(const char *mode, const char *mount_dir = NULL);
}

#endif