
#include "ledger.hpp"
#include "../crypto.hpp"
#include "../conf.hpp"
#include "../util/version.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "ledger_common.hpp"
#include "ledger_serve.hpp"

#define LEDGER_CREATE_ERROR             \
    {                                   \
        if (db != NULL)                 \
            sqlite::close_db(&db);      \
        ledger_fs.release_rw_session(); \
        return -1;                      \
    }

namespace ledger
{
    ledger_context ctx;
    ledger_record genesis;
    ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.
    ledger::ledger_serve ledger_server;     // Ledger file server instance.

    std::shared_mutex primary_index_file_mutex;

    constexpr uint32_t LEDGER_FS_ID = 1;
    constexpr int FILE_PERMS = 0644;

    /**
     * Perform ledger related initializations.
    */
    int init()
    {
        // Setup the static genesis ledger fields.
        {
            const std::string empty_hash = std::string(util::h32_empty.to_string_view());
            genesis.seq_no = 0;
            genesis.timestamp = 0;
            genesis.ledger_hash = empty_hash;
            genesis.prev_ledger_hash = empty_hash;
            genesis.data_hash = empty_hash;
            genesis.state_hash = empty_hash;
            genesis.config_hash = empty_hash;
            genesis.user_hash = empty_hash;
            genesis.input_hash = empty_hash;
            genesis.output_hash = empty_hash;
        }

        // Full history status is always set to false since this is ledger fs. Historical checkpoints are not required in ledger fs even in full history mode.
        if (ledger_fs.init(LEDGER_FS_ID, conf::ctx.ledger_hpfs_dir, conf::ctx.ledger_hpfs_mount_dir, conf::ctx.ledger_hpfs_rw_dir, false) == -1)
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
     * @param consensed_users Users and their raw inputs received in this consensus round.
     * @param generated_user_outputs Generated raw outputs in this consensus round.
     * @return Returns 0 on success -1 on error.
     */
    int save_ledger(const p2p::proposal &proposal, const consensus::consensed_user_map &consensed_users,
                    const std::map<std::string, consensus::generated_user_output> &generated_user_outputs)
    {
        // Aqure hpfs rw session before accessing shards and insert ledger records.
        if (ledger_fs.acquire_rw_session() == -1)
            return -1;

        const p2p::sequence_hash lcl_id = ctx.get_lcl_id();
        uint64_t seq_no = lcl_id.seq_no;
        seq_no++; // New ledger sequence number.

        sqlite3 *db = NULL;

        // Prepare shard folders and database and get the primary shard sequence number.
        uint64_t primary_shard_seq_no;
        if (prepare_shard(&db, primary_shard_seq_no, seq_no) == -1)
            LEDGER_CREATE_ERROR;

        // Insert primary ledger record.
        std::string new_ledger_hash;
        if (insert_ledger_record(db, lcl_id, primary_shard_seq_no, proposal, new_ledger_hash) == -1)
            LEDGER_CREATE_ERROR;

        // Save blob data.
        if ((!proposal.input_ordered_hashes.empty() || !generated_user_outputs.empty()) &&
            save_ledger_blob(new_ledger_hash, consensed_users, generated_user_outputs) == -1)
            LEDGER_CREATE_ERROR;

        // Update the latest seq_no and lcl when ledger is created.
        p2p::sequence_hash new_lcl_id;
        new_lcl_id.seq_no = seq_no;
        new_lcl_id.hash = new_ledger_hash;
        ctx.set_lcl_id(new_lcl_id);

        const std::string shard_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(primary_shard_seq_no));
        util::h32 last_primary_shard_hash;
        if (ledger_fs.get_hash(last_primary_shard_hash, hpfs::RW_SESSION_NAME, shard_vpath) == -1)
        {
            LOG_ERROR << errno << ": Error reading shard hash: " << std::to_string(primary_shard_seq_no);
            LEDGER_CREATE_ERROR;
        }

        // Update the last shard hash and shard seqence number tracker when a new ledger is created.
        ctx.set_last_primary_shard_id(p2p::sequence_hash{primary_shard_seq_no, last_primary_shard_hash});

        // Update the hpfs log index file only in full history mode.
        if (conf::cfg.node.history == conf::HISTORY::FULL && sc::contract_fs.update_hpfs_log_index() == -1)
        {
            LOG_ERROR << errno << ": Error updating the log index file.";
            return -1;
        }

        //Remove old shards that exceeds max shard range.
        if (conf::cfg.node.history == conf::HISTORY::CUSTOM && primary_shard_seq_no >= conf::cfg.node.history_config.max_primary_shards)
        {
            remove_old_shards(primary_shard_seq_no - conf::cfg.node.history_config.max_primary_shards + 1, PRIMARY_DIR);
        }

        sqlite::close_db(&db);
        return ledger_fs.release_rw_session();
    }

    /**
     * Inserts new ledger record to the sqlite database.
     * @param db Database connection to use.
     * @param current_lcl_id Current lcl id.
     * @param primary_shard_seq_no Current primary shard seq no.
     * @param proposal The consensus proposal.
     * @param new_ledger_hash Hash of the ledger that got isnerted.
     * @return 0 on success. -1 on failure.
     */
    int insert_ledger_record(sqlite3 *db, const p2p::sequence_hash &current_lcl_id, const uint64_t primary_shard_seq_no,
                             const p2p::proposal &proposal, std::string &new_ledger_hash)
    {
        // Combined binary hash of consensus user binary pub keys.
        const std::string user_hash = crypto::get_list_hash(proposal.users);

        // Combined binary hash of consensus input hashes.
        std::vector<std::string_view> inp_hashes;
        for (const std::string &o_hash : proposal.input_ordered_hashes)
        {
            // We need to consider the last 32 bytes of each ordered hash to get input hash without the nonce prefix.
            inp_hashes.push_back(util::get_string_suffix(o_hash, BLAKE3_OUT_LEN));
        }
        const std::string input_hash = crypto::get_list_hash(inp_hashes);

        uint8_t seq_no_byte_str[8], time_byte_str[8];
        util::uint64_to_bytes(seq_no_byte_str, current_lcl_id.seq_no);
        util::uint64_to_bytes(time_byte_str, proposal.time);

        // Contruct binary string for data hash.

        std::string data;
        data.reserve(sizeof(seq_no_byte_str) + sizeof(time_byte_str) + (sizeof(util::h32) * 5));
        data.append((char *)seq_no_byte_str, 8);
        data.append((char *)time_byte_str, 8);
        data.append(proposal.state_hash.to_string_view());
        data.append(proposal.patch_hash.to_string_view());
        data.append(user_hash);
        data.append(input_hash);
        data.append(proposal.output_hash);

        // Combined binary hash of data fields. blake3(seq_no + time + state_hash + patch_hash + user_hash + input_hash + output_hash)
        const std::string data_hash = crypto::get_hash(data);

        const std::string prev_ledger_hash(current_lcl_id.hash.to_string_view());

        // Ledger hash is the combined hash of previous ledger hash and the new data hash.
        new_ledger_hash = crypto::get_hash(prev_ledger_hash, data_hash);

        // Construct ledger struct with binary hashes.
        const ledger_record ledger{
            current_lcl_id.seq_no + 1,
            proposal.time,
            new_ledger_hash,
            prev_ledger_hash,
            data_hash,
            std::string(proposal.state_hash.to_string_view()),
            std::string(proposal.patch_hash.to_string_view()),
            user_hash,
            input_hash,
            proposal.output_hash}; // Merkle root output hash.

        if (sqlite::insert_ledger_row(db, ledger) == -1)
        {
            LOG_ERROR << errno << ": Error creating the ledger, shard: " << primary_shard_seq_no;
            return -1;
        }

        return 0;
    }

    /**
     * Opens a db connection to a shard and populates the shard_seq_no.
     * @param db Database connection to be openned.
     * @param ledger_seq_no Ledger sequence number.
     * @return 0 on success. -1 on failure.
     */
    int prepare_shard(sqlite3 **db, uint64_t &shard_seq_no, const uint64_t ledger_seq_no)
    {
        // Construct shard path.
        shard_seq_no = (ledger_seq_no - 1) / PRIMARY_SHARD_SIZE;
        const std::string shard_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no)));

        // If (seq_no - 1) % PRIMARY_SHARD_SIZE == 0 means this is the first ledger of the shard.
        // So create the shard folder and ledger table.
        if ((ledger_seq_no - 1) % PRIMARY_SHARD_SIZE == 0)
        {
            // Creating the directory.
            if (util::create_dir_tree_recursive(shard_path) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard, shard: " << std::to_string(shard_seq_no);
                return -1;
            }

            // Creating ledger database and open a database connection.
            if (sqlite::open_db(shard_path + "/" + DATABASE, db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
                return -1;
            }

            // Create and update the hp_version table with current hp version.
            if (sqlite::create_hp_version_table_and_update(*db, version::LEDGER_VERSION) == -1)
            {
                LOG_ERROR << errno << ": Error creating and updating hp version table, shard: " << std::to_string(shard_seq_no);
                return -1;
            }

            // Creating the ledger table.
            if (sqlite::create_ledger_table(*db) == -1)
            {
                LOG_ERROR << errno << ": Error creating the shard table, shard: " << std::to_string(shard_seq_no);
                return -1;
            }

            util::h32 prev_shard_hash;
            if (shard_seq_no > 0)
            {
                const std::string prev_shard_vpath = std::string(ledger::PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no - 1));
                if (ledger_fs.get_hash(prev_shard_hash, hpfs::RW_SESSION_NAME, prev_shard_vpath) < 1)
                {
                    LOG_ERROR << errno << ": Error getting shard hash in vpath: " << prev_shard_vpath << " for previous shard hash.";
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

            struct iovec iov_vec[2];
            iov_vec[0].iov_base = version::LEDGER_VERSION_BYTES;
            iov_vec[0].iov_len = version::VERSION_BYTES_LEN;

            iov_vec[1].iov_base = &prev_shard_hash;
            iov_vec[1].iov_len = sizeof(util::h32);

            if (writev(fd, iov_vec, 2) == -1)
            {
                LOG_ERROR << errno << ": Error writing to " << shard_hash_file_path << ".";
                close(fd);
                return -1;
            }
            close(fd);

            // Persist newly created shard seq number as the max primary shard seq number.
            if (persist_max_shard_seq_no(PRIMARY_DIR, shard_seq_no) == -1)
            {
                LOG_ERROR << "Error persisting maximum primary shard sequnce number.";
                return -1;
            }
        }
        else if (sqlite::open_db(shard_path + "/" + DATABASE, db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
            return -1;
        }

        return 0;
    }

    /**
     * Remove old shards that exceeds max shard range from file system.
     * @param led_shard_no Minimum shard number to be in history.
     */
    void remove_old_shards(const uint64_t led_shard_no, std::string_view shard_parent_dir)
    {
        // Remove old shards if this is not a full history node.
        if (conf::cfg.node.history == conf::HISTORY::CUSTOM)
        {
            for (int i = led_shard_no - 1; i >= 0; i--)
            {
                const std::string shard_path = std::string(ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_parent_dir)).append("/").append(std::to_string(i));
                // Break the loop if there's no corresponding shard.
                // There cannot be shards which is less than this shard no since shards are continous.
                if (!util::is_dir_exists(shard_path))
                    break;
                else if (util::remove_directory_recursively(shard_path) == -1)
                {
                    LOG_ERROR << errno << ": Error deleting shard: " << i;
                    break;
                }
            }
        }
    }

    /**
     * Cleanup and request historical shards according to the max we can keep.
     * @param shard_seq_no Latest shard sequence number.
     * @param shard_parent_dir Shard parent directory.
     */
    void persist_shard_history(const uint64_t shard_seq_no, std::string_view shard_parent_dir)
    {
        // Skip if shard cleanup and requesting has been already done.
        if ((shard_parent_dir == PRIMARY_DIR && ctx.primary_shards_persisted) || (shard_parent_dir == BLOB_DIR && ctx.blob_shards_persisted))
            return;

        // Set persisted flag to true. So this cleanup won't get executed again.
        shard_parent_dir == PRIMARY_DIR ? ctx.primary_shards_persisted = true : ctx.blob_shards_persisted = true;

        const std::string shard_dir_path = std::string(ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_parent_dir));
        const uint64_t max_shard_count = shard_dir_path == PRIMARY_DIR ? conf::cfg.node.history_config.max_primary_shards : conf::cfg.node.history_config.max_blob_shards;
        const std::list<std::string> shard_list = util::fetch_dir_entries(shard_dir_path);
        // Skip the sequence no file from the count.
        uint64_t shard_count = shard_list.size() - 1;

        // First, In history custom mode remove all the historical shards which are older than the min we can keep.
        if (conf::cfg.node.history == conf::HISTORY::CUSTOM && shard_seq_no >= max_shard_count)
        {
            for (const std::string &shard : shard_list)
            {
                // Skip the sequence no file.
                if (("/" + shard) == SHARD_SEQ_NO_FILENAME)
                    continue;

                uint64_t seq_no;
                if (util::stoull(shard, seq_no) != -1 && seq_no <= (shard_seq_no - max_shard_count))
                {
                    const std::string shard_path = std::string(shard_dir_path).append("/").append(shard);
                    if (util::is_dir_exists(shard_path) && util::remove_directory_recursively(shard_path) == -1)
                        LOG_ERROR << errno << ": Error deleting shard: " << shard;
                    else
                        shard_count--;
                }
            }
        }

        // In full history mode request for all the historical nodes if not exists, Otherwise request if max count haven't reached
        if (shard_seq_no >= shard_count && (conf::cfg.node.history == conf::HISTORY::FULL || shard_count < max_shard_count))
        {
            const uint64_t seq_no = shard_seq_no - shard_count;

            const std::string prev_shard_hash_file_path = shard_dir_path + "/" + std::to_string(seq_no + 1) + PREV_SHARD_HASH_FILENAME;
            const int fd = open(prev_shard_hash_file_path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd == -1)
            {
                LOG_DEBUG << "Cannot read " << prev_shard_hash_file_path;
                return;
            }

            util::h32 prev_shard_hash_from_file;
            // Start reading hash excluding version bytes.
            const int res = pread(fd, &prev_shard_hash_from_file, sizeof(util::h32), version::VERSION_BYTES_LEN);
            close(fd);
            if (res == -1)
            {
                LOG_ERROR << errno << ": Error reading hash file. " << prev_shard_hash_file_path;
                return;
            }

            const std::string sync_name = (shard_parent_dir == PRIMARY_DIR ? "primary" : "blob") + std::string(" shard ") + std::to_string(seq_no);
            const std::string shard_path = std::string(shard_parent_dir).append("/").append(std::to_string(seq_no));
            ledger_sync_worker.set_target_push_back(hpfs::sync_target{sync_name, prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
        }
    }

    /**
     * Save raw data from the consensed proposal. A blob file is only created if there is any user inputs or contract outputs
     * to save disk space.
     * @param ledger_hash Hash of this ledger we are saving.
     * @param consensed_users Users and their raw inputs consensed in this consensus round.
     * @param generated_user_outputs Generated raw outputs in this consensus round.
     * @return Returns 0 on success -1 on error.
     */
    int save_ledger_blob(std::string_view ledger_hash, const consensus::consensed_user_map &consensed_users,
                         const std::map<std::string, consensus::generated_user_output> &generated_user_outputs)
    {
        // Construct shard path.
        uint64_t last_blob_shard_seq_no = ctx.get_last_blob_shard_id().seq_no;
        std::string shard_vpath = std::string(ledger::BLOB_DIR).append("/").append(std::to_string(last_blob_shard_seq_no));
        std::string shard_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_vpath);

        bool should_create_folder = false;
        if (util::is_dir_exists(shard_path))
        {
            if ((util::fetch_dir_entries(shard_path).size() - 1) >= BLOB_SHARD_SIZE)
            {
                should_create_folder = true;
                last_blob_shard_seq_no++;
                shard_vpath = std::string(ledger::BLOB_DIR).append("/").append(std::to_string(last_blob_shard_seq_no));
                shard_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_vpath);
            }
        }
        else
        {
            should_create_folder = true;
        }

        // Create the required shard folder if not already existing.
        if (should_create_folder)
        {
            // Creating the directory.
            if (util::create_dir_tree_recursive(shard_path) == -1)
            {
                LOG_ERROR << errno << ": Error creating the blob shard, shard: " << std::to_string(last_blob_shard_seq_no);
                ledger_fs.release_rw_session();
                return -1;
            }

            util::h32 prev_shard_hash;
            if (last_blob_shard_seq_no > 0)
            {
                const std::string prev_shard_vpath = std::string(ledger::BLOB_DIR).append("/").append(std::to_string(last_blob_shard_seq_no - 1));
                if (ledger_fs.get_hash(prev_shard_hash, hpfs::RW_SESSION_NAME, prev_shard_vpath) < 1)
                {
                    LOG_ERROR << errno << ": Error getting blob shard hash in vpath: " << prev_shard_vpath << " for previous shard hash.";
                    ledger_fs.release_rw_session();
                    return -1;
                }
            }
            // Write the prev_shard.hash to the new folder.
            const std::string shard_hash_file_path = shard_path + PREV_SHARD_HASH_FILENAME;
            const int fd = open(shard_hash_file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
            if (fd == -1)
            {
                LOG_ERROR << errno << ": Error creating prev_shard.hash file in blob shard " << std::to_string(last_blob_shard_seq_no);
                return -1;
            }

            struct iovec iov_vec[2];
            iov_vec[0].iov_base = version::LEDGER_VERSION_BYTES;
            iov_vec[0].iov_len = version::VERSION_BYTES_LEN;

            iov_vec[1].iov_base = &prev_shard_hash;
            iov_vec[1].iov_len = sizeof(util::h32);

            if (writev(fd, iov_vec, 2) == -1)
            {
                LOG_ERROR << errno << ": Error writing to " << shard_hash_file_path << ".";
                close(fd);
                return -1;
            }
            close(fd);

            // Persist newly created shard seq number as the max blob shard seq number.
            if (persist_max_shard_seq_no(BLOB_DIR, last_blob_shard_seq_no) == -1)
            {
                LOG_ERROR << "Error persisting maximum blob shard sequnce number.";
                return -1;
            }
        }

        ledger_blob blob;

        blob.ledger_hash = ledger_hash;

        // Include consensed user inputs.
        for (const auto &[pubkey, inputs] : consensed_users)
        {
            const auto [itr, success] = blob.inputs.try_emplace(pubkey, std::vector<std::string>());

            for (const consensus::consensed_user_input &ci : inputs)
            {
                std::string input;
                if (usr::input_store.read_buf(ci.input, input) != -1)
                    itr->second.push_back(input);
            }
        }

        // Include consensed user outputs.
        for (const auto &[hash, user_output] : generated_user_outputs)
        {
            std::vector<std::string> outputs;
            for (const auto &output : user_output.outputs)
                outputs.push_back(std::move(output.message));

            blob.outputs.emplace(user_output.user_pubkey, std::move(outputs));
        }

        flatbuffers::FlatBufferBuilder builder(1024);
        msg::fbuf::ledgermsg::create_ledger_blob_msg_from_ledger_blob(builder, blob);

        const std::string file_path = shard_path + "/" + util::to_hex(ledger_hash) + ".blob";

        const int fd = open(file_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error creating ledger blob file. " << file_path;
            return -1;
        }

        struct iovec iov_vec[2];
        iov_vec[0].iov_base = version::LEDGER_VERSION_BYTES;
        iov_vec[0].iov_len = version::VERSION_BYTES_LEN;

        iov_vec[1].iov_base = builder.GetBufferPointer();
        iov_vec[1].iov_len = builder.GetSize();

        if (writev(fd, iov_vec, 2) == -1)
        {
            LOG_ERROR << errno << ": Error writing to ledger blob file. " << file_path;
            close(fd);
            return -1;
        }

        close(fd);

        util::h32 last_shard_hash;
        if (ledger_fs.get_hash(last_shard_hash, hpfs::RW_SESSION_NAME, shard_vpath) == -1)
        {
            LOG_ERROR << errno << ": Error reading blob shard hash: " << std::to_string(last_blob_shard_seq_no);
            ledger_fs.release_rw_session();
            return -1;
        }

        // Update the last blob shard hash and blob shard seqence number tracker when a new ledger is created.
        ctx.set_last_blob_shard_id(p2p::sequence_hash{last_blob_shard_seq_no, last_shard_hash});

        //Remove old shards that exceeds max shard range.
        if (conf::cfg.node.history == conf::HISTORY::CUSTOM && last_blob_shard_seq_no >= conf::cfg.node.history_config.max_blob_shards)
        {
            remove_old_shards(last_blob_shard_seq_no - conf::cfg.node.history_config.max_blob_shards + 1, BLOB_DIR);
        }

        return 0;
    }

    /**
     * Get last ledger and update the context.
     * @param session_name Hpfs session name.
     * @param last_primary_shard_id Last primary shard id.
     * @return Returns 0 on success -1 on error.
     */
    int get_last_ledger_and_update_context(std::string_view session_name, const p2p::sequence_hash &last_primary_shard_id)
    {
        sqlite3 *db = NULL;
        const std::string shard_path = ledger_fs.physical_path(session_name, ledger::PRIMARY_DIR) + "/" + std::to_string(last_primary_shard_id.seq_no);

        if (last_primary_shard_id.empty())
        {
            // This is the genesis ledger.
            ctx.set_lcl_id(p2p::sequence_hash{0, util::h32_empty});
            return 0;
        }

        if (sqlite::open_db(shard_path + "/" + DATABASE, &db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(last_primary_shard_id.seq_no);
            return -1;
        }

        ledger_record last_ledger;
        if (sqlite::get_last_ledger(db, last_ledger) == -1)
        {
            sqlite::close_db(&db);
            return -1;
        }

        sqlite::close_db(&db);

        // Update new lcl information.
        p2p::sequence_hash lcl_id;
        lcl_id.seq_no = last_ledger.seq_no;
        lcl_id.hash = last_ledger.ledger_hash;
        ctx.set_lcl_id(lcl_id);

        return 0;
    }

    /**
     * Get the hash and shard sequence number of the last shard in the given parent directory.
     * @param session_name Hpfs session name.
     * @param last_shard_id Struct which holds last shard data. (sequence number and hash).
     * @param shard_parent_dir Parent director vpath of the shards.
     * @return
    */
    int get_last_shard_info(std::string_view session_name, p2p::sequence_hash &last_shard_id, const std::string &shard_parent_dir)
    {
        const std::string last_shard_seq_no_vpath = shard_parent_dir + SHARD_SEQ_NO_FILENAME;
        const std::string last_shard_seq_no_path = ledger_fs.physical_path(session_name, last_shard_seq_no_vpath);

        const int fd = open(last_shard_seq_no_path.data(), O_RDONLY, FILE_PERMS);
        if (fd == -1)
        {
            if (errno == ENOENT)
            {
                LOG_DEBUG << "Max shard sequence meta file not found. Starting from zero. " << last_shard_seq_no_path;
                // Return defaults of sequence hash(0 for shard_seq_no and empty hash for shard hash).
                last_shard_id = {};
                return 0;
            }
            else
            {
                LOG_ERROR << errno << ": Error opening meta " << last_shard_seq_no_path;
                return -1;
            }
        }
        uint8_t last_shard_seq_no_buf[8];
        if (pread(fd, last_shard_seq_no_buf, sizeof(last_shard_seq_no_buf), version::VERSION_BYTES_LEN) == -1)
        {
            LOG_ERROR << errno << ": Error reading " << last_shard_seq_no_path;
            close(fd);
            return -1;
        }
        close(fd);

        last_shard_id.seq_no = util::uint64_from_bytes(last_shard_seq_no_buf);
        const std::string shard_path = std::string(shard_parent_dir).append("/").append(std::to_string(last_shard_id.seq_no));
        if (ledger_fs.get_hash(last_shard_id.hash, session_name, shard_path) == -1)
        {
            LOG_ERROR << "Error reading last shard hash in " << shard_path;
            return -1;
        }

        return 0;
    }

    /**
     * Update max_shard.seq_no meta file with the given latest shard sequence number which can be used to identify last shard 
     * sequence number in startup.
     * @param shard_parent_dir Shard's parent directory. (primary or blob).
     * @param last_shard_seq_no Last shard sequence number of the given parent.
     * @return Return -1 on error and 0 on success.
    */
    int persist_max_shard_seq_no(const std::string &shard_parent_dir, const uint64_t last_shard_seq_no)
    {
        const std::string last_shard_seq_no_vpath = shard_parent_dir + SHARD_SEQ_NO_FILENAME;
        const std::string last_shard_seq_no_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, last_shard_seq_no_vpath);

        // Open max_shard.seq_no in given parent directory.
        const int fd = open(last_shard_seq_no_path.data(), O_CREAT | O_RDWR, FILE_PERMS);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening  " << last_shard_seq_no_path;
            return -1;
        }
        uint8_t seq_no_byte_str[8];
        util::uint64_to_bytes(seq_no_byte_str, last_shard_seq_no);

        struct iovec iov_vec[2];
        iov_vec[0].iov_base = version::LEDGER_VERSION_BYTES;
        iov_vec[0].iov_len = version::VERSION_BYTES_LEN;

        iov_vec[1].iov_base = seq_no_byte_str;
        iov_vec[1].iov_len = sizeof(seq_no_byte_str);

        if (writev(fd, iov_vec, 2) == -1)
        {
            LOG_ERROR << errno << ": Error updating the max_shard.seq_no file for shard " << std::to_string(last_shard_seq_no);
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }

    /**
     * Calculate root hash of contract_fs from the ledger record of given seq_no.
     * @param root_hash The calculated root hash as of the given seq_no.
     * @param seq_no Ledger's sequence number.
     * @return Returns -1 on error and 0 on success.
    */
    int get_root_hash_from_ledger(util::h32 &root_hash, const uint64_t seq_no)
    {
        sqlite3 *db = NULL;
        const char *session_name = "root_hash_from_ledger";
        if (ledger_fs.start_ro_session(session_name, false) == -1)
            return -1;

        const uint64_t shard_seq_no = (seq_no - 1) / PRIMARY_SHARD_SIZE;

        const std::string shard_path = ledger_fs.physical_path(session_name, ledger::PRIMARY_DIR) + "/" + std::to_string(shard_seq_no);

        if (sqlite::open_db(shard_path + "/" + DATABASE, &db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
            ledger_fs.stop_ro_session(session_name);
            return -1;
        }

        ledger::ledger_record ledger;
        if (sqlite::get_ledger_by_seq_no(db, seq_no, ledger) == -1)
        {
            LOG_ERROR << "Error getting ledger by sequence number: " << std::to_string(seq_no);
            sqlite::close_db(&db);
            ledger_fs.stop_ro_session(session_name);
            return -1;
        }
        sqlite::close_db(&db);
        ledger_fs.stop_ro_session(session_name);

        root_hash = hpfs::get_root_hash(ledger.config_hash, ledger.state_hash);
        return 0;
    }
} // namespace ledger