
#include "./contract_sync.hpp"
#include "../unl.hpp"
#include "./hpfs_mount.hpp"

namespace hpfs
{

    void contract_sync::on_current_sync_state_acheived()
    {
        if (ctx.current_target.vpath == hpfs::PATCH_FILE_PATH)
        {
            // Appling new patch file changes to hpcore runtime.
            if (conf::apply_patch_config(hpfs::RW_SESSION_NAME) == -1)
            {
                LOG_ERROR << "Appling patch file changes after sync failed";
            }
            else
            {
                unl::update_unl_changes_from_patch();

                // Update global hash tracker with the new patch file hash.
                util::h32 updated_patch_hash;
                fs_mount->get_hash(updated_patch_hash, hpfs::RW_SESSION_NAME, hpfs::PATCH_FILE_PATH);
                fs_mount->set_parent_hash(ctx.current_target.vpath, updated_patch_hash);
            }
        }
    }
    void contract_sync::swap_collected_responses()
    {
        // This logic will be added to a child class in next PBI.
        std::scoped_lock lock(p2p::ctx.collected_msgs.contract_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.contract_hpfs_responses.empty())
            ctx.candidate_hpfs_responses.splice(ctx.candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.contract_hpfs_responses);
    }
} // namespace hpfs