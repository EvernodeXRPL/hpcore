#ifndef _HP_FBSCHEMA_LEDGER_HELPERS_
#define _HP_FBSCHEMA_LEDGER_HELPERS_

#include "../pchheader.hpp"
#include "ledger_schema_generated.h"
#include "../p2p/p2p.hpp"

namespace fbschema::ledger
{

const std::string_view create_ledger_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no);
}

#endif