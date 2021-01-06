#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"

namespace hpfs
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB;
    constexpr const char *RW_SESSION_NAME = "rw";  // The built-in session name used by hpfs for RW sessions.

    struct child_hash_node
    {
        bool is_file = false;
        char name[256];
        util::h32 hash;

        child_hash_node()
        {
            memset(name, 0, sizeof(name));
        }
    };

    inline uint16_t get_request_resubmit_timeout()
    {
        return conf::cfg.contract.roundtime;
    }

    enum HPFS_PARENT_COMPONENTS
    {
        STATE,
        PATCH
    };

    struct hpfs_context
    {
    private:
        std::vector<util::h32> parent_hashes;                                             // Keep hashes of each hpfs parent.
        std::shared_mutex parent_mutexes[2] = {std::shared_mutex(), std::shared_mutex()}; // Mutexes for each parent.

    public:
        pid_t hpfs_pid = 0;

        // No. of consumers for RW session.
        // We use this as a reference counting mechanism to cleanup RW session when no one requires it.
        uint32_t rw_consumers = 0;
        std::mutex rw_mutex;

        hpfs_context()
        {
            parent_hashes.reserve(2);
            for (size_t i = 0; i < 2; i++)
            {
                parent_hashes.push_back(util::h32_empty);
            }
        }

        util::h32 get_hash(const HPFS_PARENT_COMPONENTS parent)
        {
            std::shared_lock lock(parent_mutexes[parent]);
            return parent_hashes[parent];
        }

        void set_hash(const HPFS_PARENT_COMPONENTS parent, util::h32 new_state)
        {
            std::unique_lock lock(parent_mutexes[parent]);
            parent_hashes[parent] = new_state;
        }
    };

    extern hpfs_context ctx;

    int init();
    void deinit();

    int start_hpfs_process(pid_t &hpfs_pid);
    int acquire_rw_session();
    int release_rw_session();
    int start_ro_session(const std::string &name, const bool hmap_enabled);
    int stop_ro_session(const std::string &name);
    int get_hash(util::h32 &hash, const std::string &session_name, const std::string &vpath);
    int get_file_block_hashes(std::vector<util::h32> &hashes, const std::string &session_name, const std::string &vpath);
    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, const std::string &session_name, const std::string &vpath);
} // namespace hpfs

#endif