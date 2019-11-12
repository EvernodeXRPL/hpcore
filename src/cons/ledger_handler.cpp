#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/ledger_helpers.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "ledger_handler.hpp"

namespace cons
{

namespace p2pmsg = fbschema::p2pmsg;

/**
 * Create and save ledger from the given proposal message.
 * @param proposal consensus reached Satge 3 proposal.
 * @param led_seq_no next ledger sequence number.
 * @return hash of the saved lcl.
 */
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

/**
 * Retrieve lcl(last closed ledger) information from ledger history.
 * @return A ledger_history struct representing the lcl.
 */
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
        const std::string file_name = entry.path().stem().string();

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
                LOG_ERR << "Invalid lcl file name: " << file_name << " in " << conf::ctx.histDir;
            }

            if (seq_no > ldg_hist.led_seq_no)
            {
                ldg_hist.led_seq_no = seq_no;
                latest_pos = pos;
                latest_file_name = file_name; //get file name without extension.
            }
        }
    }

    //check if there is a saved lcl file -> if no send genesis lcl.
    if (latest_file_name.empty())
        ldg_hist.lcl = "genesis";
    else if ((latest_file_name.size() - 1) > latest_pos) //check position is not the end of the file name.
        ldg_hist.lcl = latest_file_name.substr(latest_pos + 1, (latest_file_name.size() - 1));
    else
        LOG_ERR << "Invalid latest file name: " << latest_file_name;

    return ldg_hist;
}

/**
 * Send ledger history request.
 * @param lcl hash of the lcl from which going to retrieve lcl history.
 */
void send_ledger_history_request(const std::string &lcl)
{
    p2p::history_request hr;
    hr.lcl = lcl;
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_history_request(msg.builder(), hr);
    p2p::send_message_to_random_peer(msg);

    LOG_DBG << "NUP sent."
            << " lcl:" << lcl;
}

/**
 * Retrieve lcl(last closed ledger) information from ledger history.
 * @return A ledger_history struct representing the lcl.
 */
const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr)
{
    p2p::history_response history_response;
    uint64_t hr_seq_no;
    for (auto &entry : boost::filesystem::directory_iterator(conf::ctx.histDir))
    {
        const boost::filesystem::path file_path = entry.path();
        const std::string file_name = entry.path().stem().string();

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
                LOG_ERR << "Invalid lcl file name: " << file_name << " in " << conf::ctx.histDir;
            }
            if ((file_name.size() - 1) > pos)
            { //check position is not the end of the file name.

                p2p::history_ledger ledger;
                ledger.lcl = file_name.substr(pos + 1, (file_name.size() - 1));

                if (ledger.lcl == hr.lcl)
                    hr_seq_no = seq_no;

                //read file
                std::ifstream file(entry.path().string(), std::ios::binary | std::ios::ate);
                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<char> buffer(size);
                if (file.read(buffer.data(), size))
                {
                    ledger.raw_ledger = reinterpret_cast<std::vector<uint8_t> &>(buffer);
                    history_response.hist_ledgers.emplace(seq_no, ledger);
                }
            }
            else
                LOG_ERR << "Invalid lcl file name: " << file_name << " in " << conf::ctx.histDir;
        }
    }

    history_response.hist_ledgers.erase(
        history_response.hist_ledgers.upper_bound(hr_seq_no),
        history_response.hist_ledgers.end());

    return history_response;
}

void ledger_history_proposal(std::string peer_session_id, const p2p::history_request &hr)
{
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));

    p2pmsg::create_msg_from_history_response(msg.builder(), retrieve_ledger_history(hr));
    p2p::send_message_to_peer(peer_session_id, msg);
}
} // namespace cons