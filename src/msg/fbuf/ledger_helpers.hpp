#ifndef _HP_MSG_FBUF_LEDGER_HELPERS_
#define _HP_MSG_FBUF_LEDGER_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_schema_generated.h"

namespace msg::fbuf::ledger
{

const std::string_view create_ledger_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no);
}

#endif