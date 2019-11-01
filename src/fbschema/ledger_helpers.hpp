#ifndef _HP_FBSCHEMA_LEDGER_HELPERS_H_
#define _HP_FBSCHEMA_LEDGER_HELPERS_H_

#include <string>
#include <unordered_set>
#include <flatbuffers/flatbuffers.h>
#include "ledger_schema_generated.h"
#include "../p2p/p2p.hpp"

namespace fbschema::ledger
{

std::string_view create_ledger_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p);
}

#endif