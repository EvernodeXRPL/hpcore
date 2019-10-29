
#include <flatbuffers/flatbuffers.h>
#include <iostream>
#include <fstream>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/ledger_schema_helpers.hpp"
#include "ledger_handler.hpp"


namespace cons
{

std::string save_ledger(const p2p::proposal &proposal)
{

    std::string_view ledger_str = fbschema::create_ledger_from_proposal(proposal);
     // auto lcl = util::hash_buffer(ledger_str, "LEDGER").hash;

    std::string stringtohash;
    stringtohash.reserve(ledger_str.length() + 6);
    stringtohash.append("LEDGER");
    stringtohash.append(ledger_str);

    std::string lcl = crypto::sha_512_hash(stringtohash);
    //save lcl
    std::string path;
    path.reserve(conf::ctx.histDir.size() + lcl.size());
    path.append(conf::ctx.histDir);
    path.append(lcl);

    std::ofstream ofs(move(path));
    ofs.write(ledger_str.data(), ledger_str.size());
    ofs.close();

    return (move(lcl));
}

void load_ledger()
{
}



} // namespace cons