#include "./contract_mount.hpp"

namespace sc
{
    /**
     * Perform contract file system mount related preparation tasks.
     * @return Returns -1 on error and 0 on success.
    */
    int contract_mount::prepare_fs()
    {
        util::h32 initial_state_hash;
        util::h32 initial_patch_hash;

        if (acquire_rw_session() == -1 ||
            conf::populate_patch_config() == -1 ||
            get_hash(initial_state_hash, hpfs::RW_SESSION_NAME, STATE_DIR_PATH) == -1 ||
            get_hash(initial_patch_hash, hpfs::RW_SESSION_NAME, PATCH_FILE_PATH) == -1 ||
            release_rw_session() == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        set_parent_hash(STATE_DIR_PATH, initial_state_hash);
        set_parent_hash(PATCH_FILE_PATH, initial_patch_hash);
        LOG_INFO << "Initial state: " << initial_state_hash << " | patch: " << initial_patch_hash;
        return 0;
    }

}