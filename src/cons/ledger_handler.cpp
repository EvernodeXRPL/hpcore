
#include <flatbuffers/flatbuffers.h>
#include <iostream>
#include <fstream>
#include <boost/filesystem.hpp>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/ledger_helpers.hpp"
#include "ledger_handler.hpp"

namespace cons
{

const std::string save_ledger(const p2p::proposal &proposal, const uint64_t led_seq_no)
{
    //Serialize lcl using flatbuffer ledger schema.
    flatbuffers::FlatBufferBuilder builder(1024);
    const std::string_view ledger_str = fbschema::ledger::create_ledger_from_proposal(builder, proposal);

    //Get binary hash of the the serialized lcl.
    const std::string lcl = crypto::get_hash(ledger_str);

    //Get hex from binary hash
    std::string lcl_hash;
    util::bin2hex(lcl_hash,
                  reinterpret_cast<const unsigned char *>(lcl.data()),
                  lcl.size());

    //create file path to save lcl.
    //file name -> [ledger sequnce numer]-[lcl hex]
    std::string path;
    std::string seq_no = std::to_string(led_seq_no);
    path.reserve(conf::ctx.histDir.size() + lcl_hash.size() + seq_no.size() + 6);
    path.append(conf::ctx.histDir);
    path.append("/");
    path.append(seq_no);
    path.append("-");
    path.append(lcl_hash);
    path.append(".lcl");

    //write lcl to file system
    std::ofstream ofs(std::move(path));
    ofs.write(ledger_str.data(), ledger_str.size());
    ofs.close();

    return (lcl_hash);
}

const ledger_history load_ledger()
{
    ledger_history ldg_hist;
    ldg_hist.led_seq_no = 0;
    // might need to load history in order to request response lcl history
    //std::unordered_map<std::string, std::string_view> lcl_history_files;

    //Get all records at lcl history direcory and find the last closed ledger.
    std::string latest_file_name;
    std::string::size_type latest_pos = 0;
    for (auto &entry : boost::filesystem::directory_iterator(conf::ctx.histDir))
    {
        const boost::filesystem::path file_path = entry.path();
        const std::string file_name = entry.path().filename().string();

        if (boost::filesystem::is_directory(file_path))
        {
            LOG_ERR << "Found directory " << file_name << " in " << conf::ctx.histDir << ". There should be no folders in this directory";
        }
        else if (file_path.extension() != ".lcl")
        {
            LOG_ERR << "Found invalid file extension: " << file_path.extension() << " for lcl file " << file_name << " in " << conf::ctx.histDir;
        }
        else
        {
            std::string::size_type pos = file_name.find("-");
            uint64_t seq_no;

            if (pos != std::string::npos)
            {
                seq_no = std::stoull(file_name.substr(0, pos));
            }
            else
            {
                //lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
                LOG_ERR << "Invalid file name: " << file_name;
            }

            if (seq_no > ldg_hist.led_seq_no)
            {
                ldg_hist.led_seq_no = seq_no;
                latest_pos = pos;
                latest_file_name = file_name;
            }
        }
    }
    
    //check if there is a saved lcl file -> if no send genesis lcl.
    if (latest_file_name.empty())
        ldg_hist.lcl = "genesis";
    else if ((latest_file_name.size() - 6) > latest_pos) //validation to check position is not the end of the file name.
        ldg_hist.lcl = latest_file_name.substr(latest_pos + 1, (latest_file_name.size() - 6));
    else
        LOG_ERR << "Invalid latest file name: " << latest_file_name;

    return ldg_hist;
}

} // namespace cons