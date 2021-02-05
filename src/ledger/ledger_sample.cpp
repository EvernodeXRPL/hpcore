
#include "ledger_sample.hpp"
#include "../crypto.hpp"
#include "../hpfs/hpfs.hpp"
#include "../conf.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"

// Currently this namespace is added for sqlite testing, later this can be modified and renamed as 'ledger::ledger_sample' -> 'ledger' for ledger implementations.
namespace ledger::ledger_sample
{
    ledger_context ctx;

    /**
     * Initialize ledger.
     * @return Returns 0 on success -1 on error.
     */
    int init()
    {
        return 0;
    }

    /**
     * Deinitialize ledger.
     */
    void deinit()
    {
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
        if (hpfs::contract_fs.acquire_rw_session() == -1)
            return -1;

        // Construct shard path.
        const uint64_t shard_no = (seq_no - 1) / SHARD_SIZE;
        const std::string shard_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH + "/" + std::to_string(shard_no);

        // If (seq_no - 1) % SHARD_SIZE == 0 means this is the first ledger of the shard.
        // So create the shard folder and ledger table.
        if ((seq_no - 1) % SHARD_SIZE == 0)
        {
            // Creating the directory.
            if (util::create_dir_tree_recursive(shard_path) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard, shard: " << std::to_string(shard_no);
                hpfs::contract_fs.release_rw_session();
                return -1;
            }

            // Creating ledger database and open a database connection.
            if (sqlite::open_db(shard_path + "/" + DATEBASE, &ctx.db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_no);
                hpfs::contract_fs.release_rw_session();
                return -1;
            }

            // Creating the ledger table.
            if (sqlite::create_ledger_table(ctx.db) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard table, shard: " << std::to_string(shard_no);
                sqlite::close_db(&ctx.db);
                hpfs::contract_fs.release_rw_session();
                return -1;
            }
        }
        else if (sqlite::open_db(shard_path + "/" + DATEBASE, &ctx.db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_no);
            hpfs::contract_fs.release_rw_session();
            return -1;
        }

        // Serialize lcl using flatbuffer ledger block schema.
        flatbuffers::FlatBufferBuilder builder(1024);
        msg::fbuf::ledger::create_ledger_block_from_proposal(builder, proposal, seq_no);

        // Get binary hash of the serialized lcl.
        std::string_view ledger_str_buf = msg::fbuf::flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
        const std::string lcl_hash = crypto::get_hash(ledger_str_buf);

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
            util::to_hex(lcl_hash),
            hash,
            util::to_hex(data_hash),
            util::to_hex(proposal.state_hash.to_string_view()),
            util::to_hex(proposal.patch_hash.to_string_view()),
            util::to_hex(user_hash),
            util::to_hex(input_hash),
            util::to_hex(proposal.output_hash));

        if (sqlite::insert_ledger_row(ctx.db, ledger) == -1)
        {
            LOG_ERROR << errno << ": Error creating the ledger, shard: " << std::to_string(shard_no);
            sqlite::close_db(&ctx.db);
            hpfs::contract_fs.release_rw_session();
            return -1;
        }

        if (update_shard_index(shard_no, shard_path) == -1)
        {
            LOG_ERROR << errno << ": Error updating shard index, shard: " << std::to_string(shard_no);
            sqlite::close_db(&ctx.db);
            hpfs::contract_fs.release_rw_session();
            return -1;
        }

        //Remove old shards that exceeds max shard range.
        if (conf::cfg.node.max_shards > 0 && shard_no >= conf::cfg.node.max_shards)
        {
            remove_old_shards(shard_no - conf::cfg.node.max_shards + 1);
        }

        sqlite::close_db(&ctx.db);
        return hpfs::contract_fs.release_rw_session();
    }

    /**
     * Remove old shards that exceeds max shard range from file system.
     * @param led_shard_no minimum shard number to be in history.
     */
    void remove_old_shards(const uint64_t &led_shard_no)
    {
        // Remove old shards if full history mode is not enabled.
        if (!conf::cfg.node.full_history)
        {
            std::string shard_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH;
            std::list<std::string> shards = util::fetch_dir_entries(shard_path);
            for (const std::string shard : shards)
            {
                if (shard != SHARD_INDEX && std::stoi(shard) < led_shard_no)
                {
                    shard_path.append("/");
                    shard_path.append(shard);
                    if (util::is_dir_exists(shard_path) && util::remove_directory_recursively(shard_path) == -1)
                    {
                        LOG_ERROR << errno << ": Error deleting shard: " << shard;
                    }
                    shard_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH;
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
     * Update hash index file with given shard.
     * @param shard_no Updated shard number.
     * @param shard_path Updated shard path.
     * @return Returns 0 on success -1 on error.
     */
    int update_shard_index(const uint64_t &shard_no, std::string_view shard_path)
    {
        util::h32 shard_hash;
        if (hpfs::contract_fs.get_hash(shard_hash, LEDGER_SESSION_NAME, shard_path) == -1)
            return -1;

        const std::string index_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH + "/" + SHARD_INDEX;
        const int fd = open(index_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening shard index file.";
            return -1;
        }

        if (pwrite(fd, shard_hash.to_string_view().data(), shard_hash.to_string_view().size(), shard_no * sizeof(util::h32)) == -1)
        {
            LOG_ERROR << errno << ": Error writing to shard index file.";
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Get the hash of a given shard from index file.
     * @param shard_hash Hash to be populated.
     * @param shard_no Shard number for the hash.
     * @return Returns 0 on success -1 on error.
     */
    int read_shard_index(util::h32 &shard_hash, const int64_t &shard_no)
    {
        const std::string index_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH + "/" + SHARD_INDEX;
        const int fd = open(index_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening shard index file.";
            return -1;
        }

        if (pread(fd, &shard_hash, sizeof(util::h32), shard_no * sizeof(util::h32)) == -1)
        {
            LOG_ERROR << errno << ": Error reading from shard index file.";
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Read whole shard index file.
     * @param shard_hash String of shard hashes to be populated.
     * @return Returns 0 on success -1 on error.
     */
    int read_shard_index(std::string &shard_hashes)
    {
        const std::string index_path = conf::ctx.ledger_rw_dir + hpfs::PRIMARY_DIR_PATH + "/" + SHARD_INDEX;
        const int fd = open(index_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening shard index file.";
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
            return -1;

        shard_hashes.resize(st.st_size);

        if (read(fd, shard_hashes.data(), shard_hashes.size()) == -1)
        {
            LOG_ERROR << errno << ": Error reading from shard index file.";
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }
} // namespace ledger::ledger_sample