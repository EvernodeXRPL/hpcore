// Code adopted from https://github.com/codetsunami/file-ptracer/blob/master/trace.cpp

#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "proc.hpp"
#include "ptrace_syscalls.hpp"

#define REG(reg) reg.orig_rax

namespace proc
{

struct fd_info
{
    std::string filepath;      // absolute path to the file
    unsigned long long cursor; // current position at which reads and writes will occur, as tracked
};

// File modifications are tracked in 4MB blocks.
static const int BLOCK_SIZE = 4 * 1024 * 1024;

/**
 * Blocks the calling thread and captures the child process activity until it exits.
 * @return 0 if child process exits normally, -1 if abnormally exited.
 */
int ptrace_capture(const pid_t child, contract_fblockmap_t &updated_blocks)
{
    // Absorb the exec notification.
    // This is because we would get a notification about execv() which is initiated by ourselves.
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    int status;
    if (!(waitpid(child, &status, 0) && !WIFEXITED(status)))
    {
        LOG_ERR << "ptrace1: Waitpid failed.";
        return -1;
    }

    /*
    egs.rdi - Stores the first argument
    regs.rsi - Stores the second argument
    regs.rdx - Stores the third argument
    regs.r10 - Stores the fourth argument
    regs.r8 - Stores the fifth argument
    regs.r9 - Stores the sixth argument
    */

    // map from child fd's to absolute filepath, updated in realtime
    std::unordered_map<int, fd_info> fd_map;

    while (true)
    {
        // this is the **first** PTRACE_SYSCALL of set of two for this system call
        // this catches the syscall BEFORE execution and provides its arguments (if any)
        // see near the end of the loop for the second
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);

        int status;
        if (!(waitpid(child, &status, 0) && !WIFEXITED(status)))
            return 0;

        // Get the registers.
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        unsigned long long scall = REG(regs);

        // this array holds 10 long words which are used to xfer the memory containing a filename
        // from the child process to this process, for calls that specify a filename
        unsigned long word_array[10];
        word_array[0] = 0;
        int has_filename = 0;
        char *filenameptr = reinterpret_cast<char *>(word_array);

        unsigned long long args[6];
        args[0] = regs.rdi;
        args[1] = regs.rsi;
        args[2] = regs.rdx;
        args[3] = regs.r10;
        args[4] = regs.r8;
        args[5] = regs.r9;

        // std::cout << "scall: " << callname(REG(regs)) << "\n";

        if (scall == SYS_creat && (has_filename = 1) ||
            scall == SYS_open && (has_filename = 1) ||
            scall == SYS_openat && (has_filename = 1) ||
            scall == SYS_chdir && (has_filename = 1) ||
            scall == SYS_close ||
            scall == SYS_lseek ||
            scall == SYS_write ||
            scall == SYS_read ||
            scall == SYS_pwrite64)
        {

            // nb: not all arguments are used by all calls

            // std::cout << callname(REG(regs)) << "(";
            // for (auto i = 0; i < 6; ++i)
            //     std::cout << args[i] << (i == 5 ? ")\n" : ", ");

            if (has_filename)
            {
                char *childptr = (scall == SYS_openat ? (char *)((void *)regs.rsi) : (char *)((void *)regs.rdi));
                for (int n = 0; n < 10; ++n)
                    word_array[n] = ptrace(PTRACE_PEEKDATA, child, childptr + (n * sizeof(unsigned long)), NULL);

                // place a \0 at the very end of the memory for string function safety
                filenameptr[sizeof(unsigned long) * 10 - 1] = '\0';
            }
        }

        // this is the **second** PTRACE_SYSCALL which provides the RETURN VALUE
        // of the syscall after it has been executed. to make use of this information
        // we need to have collected the arguments to the syscall from the first PTRACE_SYSCALL
        // near the start of the loop above
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);

        if (!(waitpid(child, &status, 0) && !WIFEXITED(status)))
            return 0;

        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        if (scall == SYS_open || scall == SYS_openat || scall == SYS_creat)
        {
            // the target application is trying to open or create a file so we need to map its fd
            int fd = (int)regs.rax;
            if (fd < 0 || fd > 0xffff)
            {
                LOG_DBG << "syscall to open, openat or creat returned invalid fd: " << fd;
                continue;
            }

            if (args[0] < 3) // we don't bother with stdin out and err: 0,1,2
                continue;

            // compute filepath
            char buf[PATH_MAX];
            realpath(filenameptr, buf);

            // We ignore anything outside the state dir.
            if (strncmp (buf, conf::ctx.statedir.c_str(), conf::ctx.statedir.size()) != 0)
                continue;

            fd_map[fd] = {std::string(buf), 0};
            // std::cout << "\tadded fd_map[" << fd << "] = " << fd_map[fd].filepath << "\n";
        }
        else if (scall == SYS_close)
        {

            // the target app is closing an fd, so check if the close was successful and if it was update our map

            if (args[0] < 3) // we don't bother with stdin out and err: 0,1,2
                continue;

            int fd = args[0];
            int result = (int)regs.rax;
            if (result != 0)
            {
                LOG_DBG << "syscall close in child did not return 0.";
                continue;
            }

            if (fd_map.find(fd) == fd_map.end())
                continue;

            fd_map.erase(fd);
        }
        else if (scall == SYS_chdir)
        {

            int result = (int)regs.rax;
            if (result != 0)
            {
                LOG_DBG << "syscall chdir in child did not return 0.";
                continue;
            }

            // the easiest way to track the child process's current working directory without explicitly
            // asking the kernel for it is just to mirror their successful chdir syscalls in the parent
            // then the parent's working directory will always match the child's working directory
            // and we can resolve all relative paths using realpath. this solution probably won't work in
            // a production setting, so real path tracking will need to be implemented
            chdir(filenameptr);
            char buf[PATH_MAX];
            getcwd(buf, PATH_MAX);
            // std::cout << "\tchanging directory to match child: '" << buf << "'\n";
        }
        else if (scall == SYS_lseek || scall == SYS_read || scall == SYS_write || scall == SYS_pwrite64)
        {
            if (args[0] < 3)
                continue;
            int offset = (int)regs.rax;
            int fd = args[0];

            if (fd_map.find(fd) == fd_map.end())
                continue;

            if (offset <= 0)
            {
                LOG_DBG << "syscall on FD: " << fd << " returned offset:" << offset << ", ignoring.";
                continue;
            }

            auto cursor_before = fd_map[fd].cursor;

            if (scall != SYS_pwrite64)
                fd_map[fd].cursor = (scall == SYS_lseek ? offset : (fd_map[fd].cursor + offset));

            auto cursor_after = fd_map[fd].cursor;

            // std::cout << "\tfd_map[" << fd << "].cursor = " << cursor_after << "\n";

            // if there's been a write we need to record it

            if (scall == SYS_write || scall == SYS_pwrite64)
            {
                const std::string &filepath = fd_map[fd].filepath;

                // compute all block boundaries
                uint32_t first_block = cursor_before / BLOCK_SIZE;
                uint32_t last_block = cursor_after / BLOCK_SIZE;

                // pwrite doesn't update cursor, but we need to record blocks changed by it
                if (scall == SYS_pwrite64)
                {
                    first_block = args[3] / BLOCK_SIZE;
                    last_block = (args[3] + offset) / BLOCK_SIZE;
                }

                // check if the map has an entry
                if (updated_blocks.find(filepath) == updated_blocks.end())
                    updated_blocks[filepath] = {}; // map should copy string here

                // add the updated blocks
                for (uint32_t i = first_block; i <= last_block; ++i)
                {
                    updated_blocks[filepath].insert(i);
                    //std::cout << "updated block " << fd_map[fd].filepath << " block " << i << "\n";
                }
            }
        }
    }

    return 0;
}

} // namespace proc