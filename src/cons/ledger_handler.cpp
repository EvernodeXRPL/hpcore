#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/ledger_helpers.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "ledger_handler.hpp"
#include "cons.hpp"

namespace cons
{

namespace p2pmsg = fbschema::p2pmsg;
std::string last_requested_lcl;

/**
 * Create and save ledger from the given proposal message.
 * @param proposal consensus reached Satge 3 proposal.
 * @param led_seq_no current ledger sequence number.
 * @return tuple of current lcl sequence number and file name of the saved lcl.
 */
const std::tuple<const uint64_t, std::string> save_ledger(const p2p::proposal &proposal)
{
    const size_t pos = proposal.lcl.find("-");
    uint64_t led_seq_no;

    if (pos != std::string::npos)
    {
        led_seq_no = std::stoull(proposal.lcl.substr(0, pos)); //get previous lcl sequence number
        led_seq_no++;                                          //current lcl sequence number
    }
    else
    {
        //lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
        LOG_ERR << "Invalid lcl name: " << proposal.lcl << " when saving ledger.";
    }

    //Serialize lcl using flatbuffer ledger schema.
    flatbuffers::FlatBufferBuilder builder(1024);
    const std::string_view ledger_str = fbschema::ledger::create_ledger_from_proposal(builder, proposal, led_seq_no);

    //Get binary hash of the the serialized lcl.
    const std::string lcl = crypto::get_hash(ledger_str);

    //Get hex from binary hash
    std::string lcl_hash;
    util::bin2hex(lcl_hash,
                  reinterpret_cast<const unsigned char *>(lcl.data()),
                  lcl.size());

    const std::string seq_no_str = std::to_string(led_seq_no);
    std::string file_name;
    file_name.reserve(lcl_hash.size() + seq_no_str.size() + 1);
    file_name.append(seq_no_str);
    file_name.append("-");
    file_name.append(lcl_hash);

    write_ledger(file_name, ledger_str.data(), ledger_str.size());

    cons::ctx.lcl_list.emplace(led_seq_no, file_name);

    if (led_seq_no > MAX_LEDGER_SEQUENCE)
    {
        remove_old_ledgers(led_seq_no);
    }

    return std::make_tuple(led_seq_no, lcl_hash);
}

void remove_old_ledgers(const uint64_t led_seq_no)
{
    std::map<uint64_t, std::string>::iterator itr;

    std::string dir_path;

    dir_path.reserve(conf::ctx.histDir.size() + 1);
    dir_path.append(conf::ctx.histDir);
    dir_path.append("/");

    for (itr = cons::ctx.lcl_list.begin();
         itr != cons::ctx.lcl_list.lower_bound(led_seq_no - MAX_LEDGER_SEQUENCE);
         itr++)
    {
        const std::string file_name = itr->second;
        std::string file_path;
        file_path.reserve(dir_path.size() + itr->second.size() + 4);
        file_path.append(dir_path);
        file_path.append(file_name);
        file_path.append(".lcl");
        boost::filesystem::remove(file_path);

        cons::ctx.lcl_list.erase(itr++);
    }
}

/**
 * Create and save ledger from the given proposal message.
 * @param led_seq_no current ledger sequence number.
 * @param lcl_hash hex name of lcl.
 * @param ledger_raw raw lcl data.
 * @param ledger_size size of raw lcl data.
 * @return file name of the saved lcl.
 */
void write_ledger(const std::string &file_name, const char *ledger_raw, size_t ledger_size)
{
    //create file path to save lcl.
    //file name -> [ledger sequnce numer]-[lcl hex]

    std::string path;

    path.reserve(file_name.size() + conf::ctx.histDir.size() + 5);
    path.append(conf::ctx.histDir);
    path.append("/");
    path.append(file_name);
    path.append(".lcl");

    //write lcl to file system
    std::ofstream ofs(std::move(path));
    ofs.write(ledger_raw, ledger_size);
    ofs.close();
}

/**
 * Retrieve lcl(last closed ledger) information from ledger history.
 * @return A ledger_history struct representing the lcl.
 */
const ledger_history load_ledger()
{
    ledger_history ldg_hist;
    //Get all records at lcl history direcory and find the last closed ledger.
    size_t latest_pos = 0;
    for (const auto &entry : boost::filesystem::directory_iterator(conf::ctx.histDir))
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
            const size_t pos = file_name.find("-");
            uint64_t seq_no;

            if (pos != std::string::npos)
            {
                seq_no = std::stoull(file_name.substr(0, pos));
                ldg_hist.lcl_list.emplace(seq_no, file_name); //lcl -> [seq_no-hash]
            }
            else
            {
                //lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
                LOG_ERR << "Invalid lcl file name: " << file_name << " in " << conf::ctx.histDir;
            }
        }
    }

    //check if there is a saved lcl file -> if no send genesis lcl.
    if (ldg_hist.lcl_list.empty())
    {
        ldg_hist.led_seq_no = 0;
        ldg_hist.lcl = "0-genesis";
    }
    else
    {
        ldg_hist.led_seq_no = ldg_hist.lcl_list.rbegin()->first;
        ldg_hist.lcl = ldg_hist.lcl_list.rbegin()->second;

        remove_old_ledgers(ldg_hist.led_seq_no);
    }

    return ldg_hist;
}

/**
 * Send ledger history request.
 * @param lcl hash of the lcl from which going to retrieve lcl history.
 */
void send_ledger_history_request(const std::string &minimum_lcl, const std::string &required_lcl)
{
    p2p::history_request hr;
    hr.required_lcl = required_lcl;
    hr.minimum_lcl = minimum_lcl;
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_history_request(msg.builder(), hr);
    p2p::send_message_to_random_peer(msg);

    last_requested_lcl = required_lcl;

    LOG_DBG << "Ledger history request sent."
            << " lcl:" << required_lcl;
}
/**
 * Check requested lcl is in lcl history cache.
 * @return true if requested lcl is in lcl history cache.
 */
bool check_required_lcl_availability(const p2p::history_request &hr)
{
    size_t pos = hr.required_lcl.find("-");
    uint64_t req_seq_no;

    LOG_DBG << "requested lcl: " << hr.required_lcl;
    LOG_DBG << "minimum lcl: " << hr.minimum_lcl;

    if (pos != std::string::npos)
    {
        req_seq_no = std::stoull(hr.required_lcl.substr(0, pos)); //get required lcl sequence number
    }

    if (req_seq_no > 0)
    {
        const auto itr = cons::ctx.lcl_list.find(req_seq_no);
        if (itr == cons::ctx.lcl_list.end())
        {
            LOG_DBG << "Required lcl peer asked for is not in our lcl cache.";
            //either this node is also not in consesnsus ledger or other node requesting a ledger that is older than maximum ledger range.
            return false;
        }
        else if (itr->second != hr.required_lcl)
        {
            LOG_DBG << "Required lcl peer asked for is not in our lcl cache.";
            //either this node or requesting node is in a fork condition.
            return false;
        }
    }
    return true;
}

/**
 * Retrieve lcl(last closed ledger) information from ledger history.
 * @return A ledger_history struct representing the lcl.
 */
const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr)
{
    p2p::history_response history_response;

    size_t pos = hr.minimum_lcl.find("-");
    uint64_t min_seq_no;

    if (pos != std::string::npos)
    {
        min_seq_no = std::stoull(hr.minimum_lcl.substr(0, pos)); //get required lcl sequence number
    }

    const auto itr = cons::ctx.lcl_list.find(min_seq_no);
    if (itr != cons::ctx.lcl_list.end())
    {
        LOG_DBG << "Minimum lcl peer asked for is not in our lcl cache. Therefore sending from node minimum lcl";

        min_seq_no = itr->first;
    }
    else
    {
        min_seq_no = cons::ctx.lcl_list.begin()->first;
    }

    auto lcl_list = cons::ctx.lcl_list;
    //filter out cache and get raw files here.
    LOG_DBG << "min seq no" << min_seq_no;
    LOG_DBG << "lower bound" << lcl_list.lower_bound(min_seq_no)->first;
    lcl_list.erase(
        lcl_list.begin(),
        lcl_list.lower_bound(min_seq_no));

    for (auto &[seq_no, lcl_hash] : lcl_list)
    {
        p2p::history_ledger ledger;
        ledger.lcl = lcl_hash;

        std::string path;

        path.reserve(conf::ctx.histDir.size() + lcl_hash.size() + 5);
        path.append(conf::ctx.histDir);
        path.append("/");
        path.append(lcl_hash);
        path.append(".lcl");

        //read file
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (file.read(buffer.data(), size))
        {
            ledger.raw_ledger = reinterpret_cast<std::vector<uint8_t> &>(buffer);
            history_response.hist_ledgers.emplace(seq_no, ledger);
        }
    }

    return history_response;
} // namespace cons

p2p::peer_outbound_message send_ledger_history(const p2p::history_request &hr)
{
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    p2pmsg::create_msg_from_history_response(msg.builder(), retrieve_ledger_history(hr));

    return msg;
}

void handle_ledger_history_response(const p2p::history_response &hr)
{
    if (last_requested_lcl.empty())
    {
        LOG_DBG << "peer sent us a history response but we never asked for one!";
        return;
    }

    bool have_equested_lcl = false;
    for (auto &[seq_no, ledger] : hr.hist_ledgers)
    {
        if (last_requested_lcl == ledger.lcl)
        {
            have_equested_lcl = true;
            break;
        }
    }

    if (!have_equested_lcl)
    {
        LOG_DBG << "peer send us a history response but not containing the lcl we asked for!";
        return;
    }

    for (auto &[seq_no, ledger] : hr.hist_ledgers)
    {
        const size_t pos = ledger.lcl.find("-");
        std::string rec_lcl_hash = ledger.lcl.substr((pos + 1), (ledger.lcl.size() - 1));

        //Get binary hash of the the serialized lcl.
        const std::string lcl = crypto::get_hash(&ledger.raw_ledger[0], ledger.raw_ledger.size());

        //Get hex from binary hash
        std::string lcl_hash;

        util::bin2hex(lcl_hash,
                      reinterpret_cast<const unsigned char *>(lcl.data()),
                      lcl.size());

        LOG_DBG << "passed lcl: " << ledger.lcl << "gen lcl: " << lcl_hash;
        if (lcl_hash != rec_lcl_hash)
        {
            LOG_WARN << "peer sent us a history response we asked for but the ledger data does not match the ledger hashes";
            //todo: we should penialzed peer who send this?
            return;
        }
    }

    for (auto &[seq_no, ledger] : hr.hist_ledgers)
    {
        write_ledger(ledger.lcl, reinterpret_cast<const char *>(&ledger.raw_ledger[0]), ledger.raw_ledger.size());
    }

    last_requested_lcl = "";
    cons::ctx.lcl = hr.hist_ledgers.rbegin()->second.lcl;
}

} // namespace cons