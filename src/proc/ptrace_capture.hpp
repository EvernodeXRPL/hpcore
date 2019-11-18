#ifndef _HP_PROC_PTRACE_CAPTURE_
#define _HP_PROC_PTRACE_CAPTURE_

#include "../pchheader.hpp"
#include "proc.hpp"

namespace proc
{
int ptrace_capture(const pid_t child, contract_fblockmap_t &updated_blocks);
}

#endif
