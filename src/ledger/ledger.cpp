
#include "ledger.hpp"
#include "../crypto.hpp"
#include "../conf.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "ledger_serve.hpp"

namespace ledger
{
    ledger_context ctx;
    constexpr uint32_t LEDGER_FS_ID = 1;
    ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.
    ledger::ledger_serve ledger_server;     // Ledger file server instance.

    std::shared_mutex primary_index_file_mutex;

    /**
     * Perform ledger related initializations.
    */
    int init()
    {
        if (ledger_fs.init(LEDGER_FS_ID, conf::ctx.ledger_hpfs_dir, conf::ctx.ledger_hpfs_mount_dir, conf::ctx.ledger_hpfs_rw_dir, conf::cfg.node.full_history) == -1)
        {
            LOG_ERROR << "Ledger file system initialization failed.";
            return -1;
        }

        if (ledger_server.init("ledger", &ledger_fs) == -1)
        {
            LOG_ERROR << "Ledger file system serve worker initialization failed.";
            return -1;
        }

        if (ledger_sync_worker.init("ledger", &ledger_fs) == -1)
        {
            LOG_ERROR << "Ledger file system sync worker initialization failed.";
            return -1;
        }

        if (get_last_ledger_and_update_context() == -1)
        {
            LOG_ERROR << "Getting last ledger faild.";
            return -1;
        }

        return 0;
    }

    /**
     * Perform deinit tasks related to ledger.
    */
    void deinit()
    {
        ledger_sync_worker.deinit();
        ledger_server.deinit();
        ledger_fs.deinit();
    }

    /**
     * Create and save ledger record from the given proposal message.
     * @param proposal Consensus-reached Stage 3 proposal.
     * @return Returns 0 on success -1 on error.
     */
    int save_ledger(const p2p::proposal &proposal)
    {
        uint64_t seq_no = 0;
        std::string hash;
        if (extract_lcl(proposal.lcl, seq_no, hash) == -1)
        {
            // lcl records should follow [ledger sequnce numer]-[lcl hex] format.
            LOG_ERROR << "Invalid lcl name: " << proposal.lcl << " when saving ledger.";
            return -1;
        }

        seq_no++; // New lcl sequence number.

        // Aqure hpfs rw session before accessing shards and insert ledger records.
        if (ledger_fs.acquire_rw_session() == -1)
            return -1;

        // Construct shard path.
        const uint64_t shard_seq_no = (seq_no - 1) / SHARD_SIZE;
        const std::string shard_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no));
        const std::string shard_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_vpath);

        // If (seq_no - 1) % SHARD_SIZE == 0 means this is the first ledger of the shard.
        // So create the shard folder and ledger table.
        if ((seq_no - 1) % SHARD_SIZE == 0)
        {
            // Creating the directory.
            if (util::create_dir_tree_recursive(shard_path) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard, shard: " << std::to_string(shard_seq_no);
                ledger_fs.release_rw_session();
                return -1;
            }

            // Creating ledger database and open a database connection.
            if (sqlite::open_db(shard_path + "/" + DATEBASE, &ctx.db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
                ledger_fs.release_rw_session();
                return -1;
            }

            // Creating the ledger table.
            if (sqlite::create_ledger_table(ctx.db) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard table, shard: " << std::to_string(shard_seq_no);
                sqlite::close_db(&ctx.db);
                ledger_fs.release_rw_session();
                return -1;
            }

            util::h32 prev_shard_hash;
            if (shard_seq_no > 0)
            {
                const std::string prev_shard_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no - 1));
                if (ledger_fs.get_hash(prev_shard_hash, hpfs::RW_SESSION_NAME, prev_shard_vpath) < 1)
                {
                    LOG_ERROR << errno << ": Error getting shard hash in vpath: " << prev_shard_vpath << " for previous shard hash.";
                    ledger_fs.release_rw_session();
                    return -1;
                }
            }
            // Write the prev_shard.hash to the new folder.
            const std::string shard_hash_file_path = shard_path + PREV_SHARD_HASH_FILENAME;
            const int fd = open(shard_hash_file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);	
            if (fd == -1)	
            {	
                LOG_ERROR << errno << ": Error creating prev_shard.hash file in shard " << std::to_string(shard_seq_no);	
                return -1;	
            }	
            if (write(fd, &prev_shard_hash, sizeof(util::h32)) == -1)	
            {	
                LOG_ERROR << errno << ": Error writing to " << shard_hash_file_path << ".";	
                close(fd);	
                return -1;	
            }
            close(fd);            
        }
        else if (sqlite::open_db(shard_path + "/" + DATEBASE, &ctx.db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
            ledger_fs.release_rw_session();
            return -1;
        }

        // Serialize lcl using flatbuffer ledger block schema.
        flatbuffers::FlatBufferBuilder builder(1024);
        msg::fbuf::ledger::create_ledger_block_from_proposal(builder, proposal, seq_no);

        // Get binary hash of the serialized lcl.
        std::string_view ledger_str_buf = msg::fbuf::flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
        const std::string lcl_hash_hex = util::to_hex(crypto::get_hash(ledger_str_buf));

        // Get binary hash of users and inputs.
        const std::string user_hash = crypto::get_hash(proposal.users);
        const std::string input_hash = crypto::get_hash(proposal.input_hashes);

        const std::string seq_no_str = std::to_string(seq_no);
        const std::string time_str = std::to_string(proposal.time);

        // Contruct binary string for data hash.
        std::string data;
        data.reserve(seq_no_str.size() + time_str.size() + (32 * 5));
        data.append(seq_no_str);
        data.append(time_str);
        data.append(proposal.state_hash.to_string_view());
        data.append(proposal.patch_hash.to_string_view());
        data.append(user_hash);
        data.append(input_hash);
        data.append(proposal.output_hash);

        // Get binary hash of data.
        const std::string data_hash = crypto::get_hash(data);

        // Construct ledger struct.
        // Hashes are stored as hex string;
        const sqlite::ledger ledger(
            seq_no,
            proposal.time,
            lcl_hash_hex,
            hash,
            util::to_hex(data_hash),
            util::to_hex(proposal.state_hash.to_string_view()),
            util::to_hex(proposal.patch_hash.to_string_view()),
            util::to_hex(user_hash),
            util::to_hex(input_hash),
            util::to_hex(proposal.output_hash));

        if (sqlite::insert_ledger_row(ctx.db, ledger) == -1)
        {
            LOG_ERROR << errno << ": Error creating the ledger, shard: " << std::to_string(shard_seq_no);
            sqlite::close_db(&ctx.db);
            ledger_fs.release_rw_session();
            return -1;
        }

        // Update the seq_no and lcl when ledger is created.
        const std::string new_lcl = std::string(std::to_string(seq_no)).append("-").append(lcl_hash_hex);
        ctx.set_lcl(seq_no, new_lcl);

        util::h32 last_shard_hash;
        if (ledger_fs.get_hash(last_shard_hash, hpfs::RW_SESSION_NAME, shard_vpath) == -1)
        {
            LOG_ERROR << errno << ": Error reading shard hash: " << std::to_string(shard_seq_no);
            sqlite::close_db(&ctx.db);
            ledger_fs.release_rw_session();
            return -1;
        }

        // Update the last shard hash and shard seqence number tracker when a new ledger is created.
        ctx.set_last_shard_hash(shard_seq_no, last_shard_hash);

        //Remove old shards that exceeds max shard range.
        if (conf::cfg.node.max_shards > 0 && shard_seq_no >= conf::cfg.node.max_shards)
        {
            remove_old_shards(shard_seq_no - conf::cfg.node.max_shards + 1);
        }

        sqlite::close_db(&ctx.db);
        return ledger_fs.release_rw_session();
    }

    /**
     * Remove old shards that exceeds max shard range from file system.
     * @param led_shard_no minimum shard number to be in history.
     */
    void remove_old_shards(const uint64_t led_shard_no)
    {
        // Remove old shards if full history mode is not enabled.
        if (!conf::cfg.node.full_history)
        {
            const std::string shard_dir_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, ledger::PRIMARY_DIR);
            std::list<std::string> shards = util::fetch_dir_entries(shard_dir_path);
            for (const std::string shard : shards)
            {
                uint64_t shard_seq_no;
                util::stoull(shard, shard_seq_no);
                if (shard_seq_no < led_shard_no)
                {
                    const std::string shard_path = std::string(shard_dir_path).append("/").append(shard);
                    if (util::is_dir_exists(shard_path) && util::remove_directory_recursively(shard_path) == -1)
                    {
                        LOG_ERROR << errno << ": Error deleting shard: " << shard;
                    }
                }
            }
        }
    }

    /**
     * Extract seq_no and hash from lcl.
     * @param lcl lcl to be extracted.
     * @param seq_no Extracted sequence number.
     * @param hash Extracted hash.
     * @return Returns 0 on success -1 on error.
     */
    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash)
    {
        if (lcl == GENESIS_LEDGER)
        {
            seq_no = 0;
            hash = lcl.substr(2);
            return 0;
        }

        const size_t pos = lcl.find("-");
        if (pos == std::string::npos)
            return -1;

        if (util::stoull(lcl.substr(0, pos), seq_no) == -1)
            return -1;

        hash = lcl.substr(pos + 1);
        if (hash.size() != 64)
            return -1;

        return 0;
    }

    /**
     * Get last ledger and update the context.
     * @return Returns 0 on success -1 on error.
     */
    int get_last_ledger_and_update_context()
    {
        // Aquire hpfs rw session before accessing shards and insert ledger records.
        if (ledger_fs.acquire_rw_session() == -1)
            return -1;

        const std::string shard_dir_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, ledger::PRIMARY_DIR);
        std::list<std::string> shards = util::fetch_dir_entries(shard_dir_path);

        if (shards.size() == 0)
        {
            ledger_fs.release_rw_session();
            ctx.set_lcl(0, GENESIS_LEDGER);
        }
        else
        {
            shards.sort([](std::string &a, std::string &b) {
                uint64_t seq_no_a, seq_no_b;
                util::stoull(a, seq_no_a);
                util::stoull(b, seq_no_b);
                return seq_no_a > seq_no_b;
            });

            uint64_t last_shard_seq_no;
            util::stoull(shards.front(), last_shard_seq_no);
            const std::string shard_path = std::string(shard_dir_path).append("/").append(shards.front());

            //Remove old shards that exceeds max shard range.
            if (conf::cfg.node.max_shards > 0 && shards.size() >= conf::cfg.node.max_shards)
            {
                remove_old_shards(last_shard_seq_no - conf::cfg.node.max_shards + 1);
            }

            // Open a database connection.
            if (sqlite::open_db(shard_path + "/" + DATEBASE, &ctx.db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << shards.front();
                ledger_fs.release_rw_session();
                return -1;
            }

            sqlite::ledger last_ledger = sqlite::get_last_ledger(ctx.db);
            sqlite::close_db(&ctx.db);

            ctx.set_lcl(last_ledger.seq_no, std::to_string(last_ledger.seq_no) + "-" + last_ledger.ledger_hash_hex);

            util::h32 last_shard_hash;
            const std::string shard_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(shards.front());
            const int ret = ledger_fs.get_hash(last_shard_hash, hpfs::RW_SESSION_NAME, shard_vpath);
            if (ret == -1)
            {
                LOG_ERROR << errno << ": Error reading shard hash: " << shards.front();
                ledger_fs.release_rw_session();
                return -1;
            }
            if (ret == 1)
                ctx.set_last_shard_hash(last_shard_seq_no, last_shard_hash);
            ledger_fs.release_rw_session();
        }

        return 0;
    }

    /**
     * Get the hash and shard sequence number of the last shard in the ledger primary directory.
     * @param session_name Hpfs session name.
     * @param last_shard_hash Hash of the last shard.
     * @param shard_seq_no Shard sequence number of the last shard.
     * @return
    */
    int get_last_shard_info(std::string_view session_name, util::h32 &last_shard_hash, uint64_t &shard_seq_no)
    {
        const std::string shard_dir_path = ledger_fs.physical_path(session_name, ledger::PRIMARY_DIR);
        std::list<std::string> shards = util::fetch_dir_entries(shard_dir_path);

        if (shards.size() > 0)
        {
            shards.sort([](std::string &a, std::string &b) {
                uint64_t seq_no_a, seq_no_b;
                util::stoull(a, seq_no_a);
                util::stoull(b, seq_no_b);
                return seq_no_a > seq_no_b;
            });

            const std::string shard_path = std::string(ledger::PRIMARY_DIR).append("/").append(shards.front());
            if (ledger_fs.get_hash(last_shard_hash, session_name, shard_path) == -1 || util::stoull(shards.front(), shard_seq_no) == -1)
            {
                LOG_ERROR << "Error reading last shard hash in " << shard_path;
                return -1;
            }
        }
        return 0;
    }
} // namespace ledger