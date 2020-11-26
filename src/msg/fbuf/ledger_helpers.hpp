#ifndef _HP_MSG_FBUF_LEDGER_HELPERS_
#define _HP_MSG_FBUF_LEDGER_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_schema_generated.h"

namespace msg::fbuf::ledger
{

    void create_ledger_block_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no);

    p2p::proposal create_proposal_from_ledger_block(const std::vector<uint8_t> &ledger_buf);

    bool verify_ledger_block_buffer(const uint8_t *ledger_buf_ptr, const size_t buf_len);

    void create_full_history_block_from_raw_input_map(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, usr::raw_user_input> &map);

    std::unordered_map<std::string, usr::raw_user_input> create_raw_input_map_from_full_history_block(const std::vector<uint8_t> &fullhist_buf);
} // namespace msg::fbuf::ledger

#endif