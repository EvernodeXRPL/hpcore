#include "pchheader.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "p2p/p2p.hpp"
#include "msg/fbuf/common_helpers.hpp"
#include "msg/fbuf/ledger_helpers.hpp"
#include "msg/fbuf/p2pmsg_helpers.hpp"
#include "hplog.hpp"
#include "ledger.hpp"
#include "cons/cons.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace ledger
{
    constexpr int FILE_PERMS = 0644;
    constexpr uint64_t MAX_LEDGER_SEQUENCE = 200; // Max ledger count.
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    ledger_context ctx;

    /**
     * Retrieve ledger history information from persisted ledgers.
     */
    int init()
    {
        // Get all records at lcl history direcory and find the last closed ledger.
        size_t latest_pos = 0;
        for (const auto &entry : util::fetch_dir_entries(conf::ctx.hist_dir))
        {
            const std::string file_path = conf::ctx.hist_dir + "/" + entry.d_name;

            if (util::is_dir_exists(file_path))
            {
                LOG_ERROR << "Found directory " << entry.d_name << " in " << conf::ctx.hist_dir << ". There should be no folders in this directory.";
                return -1;
            }
            else
            {
                const std::string_view extension = util::fetch_file_extension(file_path);
                const std::string file_name(util::remove_file_extension(entry.d_name));

                if (extension != ".lcl")
                {
                    LOG_ERROR << "Found invalid file extension: " << extension << " for lcl file " << entry.d_name << " in " << conf::ctx.hist_dir;
                    return -1;
                }

                const size_t pos = file_name.find("-");
                uint64_t seq_no = 0;

                if (pos != std::string::npos)
                {
                    seq_no = std::stoull(file_name.substr(0, pos));

                    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);

                    std::vector<char> buffer(size);
                    if (file.read(buffer.data(), size))
                    {
                        const uint8_t *ledger_buf_ptr = reinterpret_cast<const uint8_t *>(buffer.data());
                        const msg::fbuf::ledger::Ledger *ledger = msg::fbuf::ledger::GetLedger(ledger_buf_ptr);
                        ledger_cache_entry c;
                        c.lcl = file_name;
                        c.state = msg::fbuf::flatbuff_bytes_to_sv(ledger->state());

                        ctx.cache.emplace(seq_no, std::move(c)); //lcl_cache -> [seq_no-hash]
                    }
                }
                else
                {
                    // lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
                    LOG_ERROR << "Invalid lcl file name: " << file_name << " in " << conf::ctx.hist_dir;
                    return -1;
                }
            }
        }

        // Check if there is a saved lcl file -> if no send genesis lcl.
        if (ctx.cache.empty())
        {
            ctx.led_seq_no = 0;
            ctx.lcl = GENESIS_LEDGER;
        }
        else
        {
            const auto last_ledger = ctx.cache.rbegin();
            ctx.led_seq_no = last_ledger->first;
            ctx.lcl = last_ledger->second.lcl;

            // Remove old ledgers that exceeds max sequence range.
            if (ctx.led_seq_no > MAX_LEDGER_SEQUENCE)
                remove_old_ledgers(ctx.led_seq_no - MAX_LEDGER_SEQUENCE);
        }

        return 0;
    }

    /**
     * Create and save ledger from the given proposal message.
     * @param proposal Consensus-reached Satge 3 proposal.
     */
    int save_ledger(const p2p::proposal &proposal)
    {
        const size_t pos = proposal.lcl.find("-");
        uint64_t led_seq_no = 0;

        if (pos != std::string::npos)
        {
            led_seq_no = std::stoull(proposal.lcl.substr(0, pos)); //get lcl sequence number.
            led_seq_no++;                                          //current lcl sequence number.
        }
        else
        {
            // lcl records should follow [ledger sequnce numer]-lcl[lcl hex] format.
            LOG_ERROR << "Invalid lcl name: " << proposal.lcl << " when saving ledger.";
            return -1;
        }

        // Serialize lcl using flatbuffer ledger schema.
        flatbuffers::FlatBufferBuilder builder(1024);
        const std::string_view ledger_str = msg::fbuf::ledger::create_ledger_from_proposal(builder, proposal, led_seq_no);

        // Get binary hash of the the serialized lcl.
        const std::string lcl = crypto::get_hash(ledger_str);

        // Get hex from binary hash.
        std::string lcl_hash;
        util::bin2hex(lcl_hash,
                      reinterpret_cast<const unsigned char *>(lcl.data()),
                      lcl.size());

        // Construct lcl file name.
        // lcl file name should follow [ledger sequnce numer]-lcl[lcl hex] format.
        const std::string file_name = std::to_string(led_seq_no) + "-" + lcl_hash;
        if (write_ledger_contents(file_name, ledger_str.data(), ledger_str.size()) == -1)
            return -1;

        ledger_cache_entry c;
        c.lcl = file_name;
        c.state = proposal.state.to_string_view();
        ctx.cache.emplace(led_seq_no, std::move(c));

        //Remove old ledgers that exceeds max sequence range.
        if (led_seq_no > MAX_LEDGER_SEQUENCE)
            remove_old_ledgers(led_seq_no - MAX_LEDGER_SEQUENCE);

        return 0;
    }

    /**
     * Remove old ledgers that exceeds max sequence range from file system and ledger history cache.
     * @param led_seq_no minimum sequence number to be in history.
     */
    void remove_old_ledgers(const uint64_t led_seq_no)
    {
        std::map<uint64_t, ledger_cache_entry>::iterator itr;

        for (itr = ctx.cache.begin();
             itr != ctx.cache.lower_bound(led_seq_no + 1);
             itr++)
        {
            const std::string file_path = conf::ctx.hist_dir + "/" + itr->second.lcl + ".lcl";

            if (util::is_file_exists(file_path))
                util::remove_file(file_path);
        }

        if (!ctx.cache.empty())
            ctx.cache.erase(ctx.cache.begin(), ctx.cache.lower_bound(led_seq_no + 1));
    }

    /**
     * Write ledger to file system.
     * @param file_name current ledger sequence number.
     * @param ledger_raw raw lcl data.
     * @param ledger_size size of the raw lcl data.
     */
    int write_ledger_contents(const std::string &file_name, const char *ledger_raw, const size_t ledger_size)
    {
        // Create file path to save ledger.
        // file name -> [ledger sequnce numer]-[lcl hex]

        const std::string file_path = conf::ctx.hist_dir + "/" + file_name + ".lcl";

        // Write ledger to file system
        const int fd = open(file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error creating ledger file. " << file_path;
            return -1;
        }

        if (write(fd, ledger_raw, ledger_size) == -1)
        {
            LOG_ERROR << errno << ": Error writing to new ledger file. " << file_path;
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Delete ledger from file system.
     * @param file_name name of ledger to be deleted.
     */
    void remove_ledger(const std::string &file_name)
    {
        std::string file_path;
        file_path.reserve(conf::ctx.hist_dir.size() + file_name.size() + 5);
        file_path.append(conf::ctx.hist_dir)
            .append("/")
            .append(file_name)
            .append(".lcl");
        util::remove_file(file_path);
    }

    /**
     * Create and send ledger history request to random node from unl list.
     * @param minimum_lcl hash of the minimum lcl from which node need lcl history.
     * @param required_lcl hash of the required lcl.
     */
    void send_ledger_history_request(const std::string &minimum_lcl, const std::string &required_lcl)
    {
        p2p::history_request hr;
        hr.required_lcl = required_lcl;
        hr.minimum_lcl = minimum_lcl;

        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_history_request(fbuf, hr);
        p2p::send_message_to_random_peer(fbuf);

        ctx.last_requested_lcl = required_lcl;

        LOG_DEBUG << "Ledger history request sent. Required lcl:" << required_lcl.substr(0, 15);
    }

    /**
     * Check requested lcl is in node's lcl history cache.
     * @param hr lcl history request information.
     * @return true if requested lcl is in lcl history cache.
     */
    bool check_required_lcl_availability(const p2p::history_request &hr)
    {
        size_t pos = hr.required_lcl.find("-");
        uint64_t req_seq_no = 0;

        // Get sequence number of required lcl
        if (pos != std::string::npos)
        {
            req_seq_no = std::stoull(hr.required_lcl.substr(0, pos)); // Get required lcl sequence number
        }

        if (req_seq_no > 0)
        {
            const auto itr = ctx.cache.find(req_seq_no);
            if (itr == ctx.cache.end())
            {
                LOG_DEBUG << "Required lcl peer asked for is not in our lcl cache.";
                // Either this node is also not in consesnsus ledger or other node requesting a lcl that is older than node's current
                // minimum lcl sequence becuase of maximum ledger history range.
                return false;
            }
            else if (itr->second.lcl != hr.required_lcl)
            {
                LOG_DEBUG << "Required lcl peer asked for is not in our lcl cache.";
                // Either this node or requesting node is in a fork condition.
                return false;
            }
        }
        else
        {
            return false; //Very rare case: node asking for the genisis lcl.
        }
        return true;
    }

    /**
     * Retrieve lcl(last closed ledger) information from ledger history.
     * @param hr lcl history request information.
     * @return A ledger history response containing requested ledger details.
     */
    const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr)
    {
        p2p::history_response history_response;
        size_t pos = hr.minimum_lcl.find("-");
        uint64_t min_seq_no = 0;

        //get sequence number of minimum lcl required
        if (pos != std::string::npos)
        {
            min_seq_no = std::stoull(hr.minimum_lcl.substr(0, pos)); //get required lcl sequence number
        }

        const auto itr = ctx.cache.find(min_seq_no);
        if (itr != ctx.cache.end()) //requested minimum lcl is not in our lcl history cache
        {
            min_seq_no = itr->first;
            //check whether minimum lcl node ask for is same as this node's.
            //eventhough sequence number are same, lcl hash can be changed if one of node is in a fork condition.
            if (hr.minimum_lcl != itr->second.lcl)
            {
                LOG_DEBUG << "Invalid minimum ledger. Recieved min hash: " << hr.minimum_lcl << " Node hash: " << itr->second.lcl;
                history_response.error = p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER;
                return history_response;
            }
        }
        else if (min_seq_no > ctx.cache.rbegin()->first) //Recieved minimum lcl sequence is ahead of node's lcl sequence.
        {
            LOG_DEBUG << "Invalid minimum ledger. Recieved minimum sequence number is ahead of node current lcl sequence. Recvd hash: " << hr.minimum_lcl;
            history_response.error = p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER;
            return history_response;
        }
        else
        {
            LOG_DEBUG << "Minimum lcl peer asked for is not in our lcl cache. Therefore sending from node minimum lcl";
            min_seq_no = ctx.cache.begin()->first;
        }

        //LOG_DBG << "history request min seq: " << std::to_string(min_seq_no);

        //copy current history cache.
        std::map<uint64_t, ledger_cache_entry> led_cache = ctx.cache;

        //filter out cache and get raw files here.
        led_cache.erase(
            led_cache.begin(),
            led_cache.lower_bound(min_seq_no));

        //Get raw content of lcls that going to be send.
        for (auto &[seq_no, cache] : led_cache)
        {
            p2p::history_ledger ledger;
            ledger.lcl = cache.lcl;
            ledger.state = cache.state;

            std::string path;

            path.reserve(conf::ctx.hist_dir.size() + cache.lcl.size() + 5);
            path.append(conf::ctx.hist_dir)
                .append("/")
                .append(cache.lcl)
                .append(".lcl");

            //read lcl file
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
    }

    /**
     * Handle recieved ledger history response.
     * @param hr lcl history request information.
     * @return peer outbound message object with ledger history response.
     */
    void handle_ledger_history_response(const p2p::history_response &hr)
    {
        // Check response object contains
        if (ctx.last_requested_lcl.empty())
        {
            LOG_DEBUG << "Peer sent us a history response but we never asked for one!";
            return;
        }

        if (hr.error == p2p::LEDGER_RESPONSE_ERROR::INVALID_MIN_LEDGER)
        {
            // This means we are in a fork ledger.Remove/rollback current ledger.
            // Basically in the long run we'll rolback one by one untill we catch up to valid minimum ledger .
            remove_ledger(ctx.lcl);
            ctx.cache.erase(ctx.cache.rbegin()->first);
            LOG_DEBUG << "Invalid min ledger. Removed last ledger.";
        }
        else
        {
            // Check whether recieved lcl history contains the current lcl node required.
            bool have_requested_lcl = false;
            for (auto &[seq_no, ledger] : hr.hist_ledgers)
            {
                if (ctx.last_requested_lcl == ledger.lcl)
                {
                    have_requested_lcl = true;
                    break;
                }
            }

            if (!have_requested_lcl)
            {
                LOG_DEBUG << "Peer sent us a history response but not containing the lcl we asked for! " << hr.hist_ledgers.size();
                return;
            }

            // Check integrity of recieved lcl list.
            // By checking recieved lcl hashes matches lcl content by applying hashing for each raw content.
            for (auto &[seq_no, ledger] : hr.hist_ledgers)
            {
                const size_t pos = ledger.lcl.find("-");
                std::string rec_lcl_hash = ledger.lcl.substr((pos + 1), (ledger.lcl.size() - 1));

                // Get binary hash of the the serialized lcl.
                const std::string lcl = crypto::get_hash(&ledger.raw_ledger[0], ledger.raw_ledger.size());

                // Get hex from binary hash
                std::string lcl_hash;

                util::bin2hex(lcl_hash,
                              reinterpret_cast<const unsigned char *>(lcl.data()),
                              lcl.size());

                // LOG_DBG << "passed lcl: " << ledger.lcl << " gen lcl: " << lcl_hash;

                // recieved lcl hash and hash generated from recieved lcl content doesn't match -> abandon applying it
                if (lcl_hash != rec_lcl_hash)
                {
                    LOG_WARNING << "peer sent us a history response we asked for but the ledger data does not match the ledger hashes";
                    // todo: we should penalize peer who send this?
                    return;
                }
            }
        }

        // Execution to here means the history data sent checks out
        // Save recieved lcl in file system and update lcl history cache
        for (auto &[seq_no, ledger] : hr.hist_ledgers)
        {
            auto prev_dup_itr = ctx.cache.find(seq_no);
            if (prev_dup_itr != ctx.cache.end())
            {
                remove_ledger(prev_dup_itr->second.lcl);
                ctx.cache.erase(prev_dup_itr);
            }

            write_ledger_contents(ledger.lcl, reinterpret_cast<const char *>(&ledger.raw_ledger[0]), ledger.raw_ledger.size());

            ledger_cache_entry l;
            l.lcl = ledger.lcl;
            l.state = ledger.state;
            ctx.cache.emplace(seq_no, std::move(l));
        }

        ctx.last_requested_lcl = "";

        if (ctx.cache.empty())
        {
            ctx.led_seq_no = 0;
            ctx.lcl = GENESIS_LEDGER;
        }
        else
        {
            const auto latest_lcl_itr = ctx.cache.rbegin();
            ctx.lcl = latest_lcl_itr->second.lcl;
            ctx.led_seq_no = latest_lcl_itr->first;
        }

        LOG_INFO << "lcl sync complete. New lcl:" << ctx.lcl.substr(0, 15);
    }

} // namespace ledger