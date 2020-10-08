#ifndef _HP_CONS_STATE_SERVE_
#define _HP_CONS_STATE_SERVE_

#include "../hpfs/h32.hpp"
#include "../hpfs/hpfs.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"

namespace state_serve
{
    int init();

    void deinit();
    
    void state_serve_loop();

    int create_state_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::state_request &sr, std::string_view lcl);

    int get_data_block(std::vector<uint8_t> &vec, const std::string_view vpath,
                       const uint32_t block_id, const hpfs::h32 expected_hash);

    int get_data_block_hashes(std::vector<hpfs::h32> &hashes, size_t &file_length,
                              const std::string_view vpath, const hpfs::h32 expected_hash);

    int get_fs_entry_hashes(std::vector<hpfs::child_hash_node> &hash_nodes,
                                const std::string_view vpath, const hpfs::h32 expected_hash);
} // namespace state_sync

#endif