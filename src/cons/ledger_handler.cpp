
#include <flatbuffers/flatbuffers.h>
#include <iostream>
#include <fstream>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/ledger_helpers.hpp"
#include "ledger_handler.hpp"

namespace cons
{

std::string save_ledger(const p2p::proposal &proposal)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    std::string_view ledger_str = fbschema::ledger::create_ledger_from_proposal(builder, proposal);

    const std::string lcl = crypto::sha_512_hash(ledger_str);

    std::string lcl_hash;
    util::bin2hex(lcl_hash,
                  reinterpret_cast<const unsigned char *>(lcl.data()),
                  lcl.size());

    //save lcl
    std::string path;
    path.reserve(conf::ctx.histDir.size() + lcl_hash.size() + 1);
    path.append(conf::ctx.histDir);
    path.append("/");
    path.append(lcl_hash);

    std::ofstream ofs(move(path));
    ofs.write(ledger_str.data(), ledger_str.size());
    ofs.close();

    return (move(lcl));
}

void load_ledger()
{
}

} // namespace cons