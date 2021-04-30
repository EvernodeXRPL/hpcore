#ifndef _HP_HPFS_HPFS_SERVE_
#define _HP_HPFS_HPFS_SERVE_

#include "../util/h32.hpp"
#include "hpfs_mount.hpp"
#include "../p2p/p2p.hpp"

namespace hpfs
{
    class hpfs_serve
    {
    private:
        bool is_shutting_down = false;
        bool init_success = false;
        std::thread hpfs_serve_thread;
        hpfs::hpfs_mount *fs_mount = NULL;
        std::string_view name;
        void hpfs_serve_loop();
        int generate_sync_responses(std::vector<flatbuffers::FlatBufferBuilder> &fbuf_vec, const p2p::hpfs_request &hr);
        void generate_reply_fs_entries(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries, std::vector<p2p::hpfs_fs_hash_entry> &respond_fs_entries,
                                       const std::vector<p2p::hpfs_fs_hash_entry> &fs_entry_hints);
        void generate_hint_responses(std::vector<flatbuffers::FlatBufferBuilder> &fbuf_vec, const std::string &parent_path, const std::vector<p2p::hpfs_fs_hash_entry> &fs_entries);

        int get_data_block_with_hash_check(std::vector<uint8_t> &block, const std::string_view vpath,
                                           const uint32_t block_id, const util::h32 expected_hash);
        int get_data_block_hashes_with_hash_check(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode,
                                                  const std::string_view vpath, const util::h32 expected_hash);
        int get_fs_entry_hashes_with_hash_check(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries,
                                                const std::string_view vpath, const util::h32 expected_hash);

        int get_data_block(std::vector<uint8_t> &block, const std::string_view vpath, const uint32_t block_id);
        int get_data_block_hashes(std::vector<util::h32> &hashes, size_t &file_length, mode_t &file_mode, const std::string_view vpath);
        int get_fs_entry_hashes(std::vector<p2p::hpfs_fs_hash_entry> &fs_entries, const std::string_view vpath);

    protected:
        std::list<std::pair<std::string, p2p::hpfs_request>> hpfs_requests;
        // Move the collected requests from hpfs requests to a local response list.
        virtual void swap_collected_requests() = 0; // Must override in child classes.

    public:
        int init(std::string_view server_name, hpfs::hpfs_mount *fs_mount_ptr);

        void deinit();
    };
} // namespace hpfs

#endif