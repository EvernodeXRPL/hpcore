
#include "ledger.hpp"
#include "../crypto.hpp"
#include "../conf.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/ledger_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
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
     * @param candidate_user_inputs Raw inputs received in this consensus round.
     * @param generated_user_outputs Generated raw outputs in this consensus round.
     * @return Returns 0 on success -1 on error.
     */
    int save_ledger(const p2p::proposal &proposal, const std::map<std::string, consensus::candidate_user_input> &candidate_user_inputs,
                    const std::map<std::string, consensus::generated_user_output> &generated_user_outputs)
    {
        const p2p::sequence_hash lcl_id = ctx.get_lcl_id();
        uint64_t seq_no = lcl_id.seq_no;
        const std::string prev_ledger_hash(lcl_id.hash.to_string_view());

        seq_no++; // New lcl sequence number.

        // Aqure hpfs rw session before accessing shards and insert ledger records.
        if (ledger_fs.acquire_rw_session() == -1)
            return -1;

        sqlite3 *db = NULL;

        // Prepare shard folders and database and get the primary shard sequence number.
        uint64_t primary_shard_seq_no;
        if (prepare_shard(&db, primary_shard_seq_no, seq_no) == -1)
            LEDGER_CREATE_ERROR;

        // Combined binary hash of consensus user binary pub keys.
        const std::string user_hash = crypto::get_hash(proposal.users);
        // Combined binary hash of consensus input hashes.
        const std::string input_hash = crypto::get_hash(proposal.input_hashes);

        uint8_t seq_no_byte_str[8], time_byte_str[8];
        util::uint64_to_bytes(seq_no_byte_str, seq_no);
        util::uint64_to_bytes(time_byte_str, proposal.time);

        // Contruct binary string for data hash.

        std::string data;
        data.reserve(sizeof(seq_no_byte_str) + sizeof(time_byte_str) + (sizeof(util::h32) * 5));
        data.append((char *)seq_no_byte_str);
        data.append((char *)time_byte_str);
        data.append(proposal.state_hash.to_string_view());
        data.append(proposal.patch_hash.to_string_view());
        data.append(user_hash);
        data.append(input_hash);
        data.append(proposal.output_hash);

        // Combined binary hash of data fields. blake3(seq_no + time + state_hash + patch_hash + user_hash + input_hash + output_hash)
        const std::string data_hash = crypto::get_hash(data);

        // Ledger hash is the combined hash of previous ledger hash and the new data hash.
        const std::string ledger_hash = crypto::get_hash(prev_ledger_hash, data_hash);
        const std::string ledger_hash_hex = util::to_hex(ledger_hash);
        // Construct ledger struct.
        // Hashes are stored as hex string;
        const sqlite::ledger ledger(
            seq_no,
            proposal.time,
            ledger_hash_hex,
            util::to_hex(prev_ledger_hash),
            util::to_hex(data_hash),
            util::to_hex(proposal.state_hash.to_string_view()),
            util::to_hex(proposal.patch_hash.to_string_view()),
            util::to_hex(user_hash),
            util::to_hex(input_hash),
            util::to_hex(proposal.output_hash)); // Merkle root output hash.

        if (sqlite::insert_ledger_row(db, ledger) == -1)
        {
            LOG_ERROR << errno << ": Error creating the ledger, shard: " << std::to_string(primary_shard_seq_no);
            LEDGER_CREATE_ERROR;
        }

        if ((!candidate_user_inputs.empty() || !generated_user_outputs.empty()) && save_ledger_blob(ledger_hash, candidate_user_inputs, generated_user_outputs) == -1)
        {
            LOG_ERROR << errno << ": Error saving the raw inputs/outputs, shard: " << std::to_string(primary_shard_seq_no);
            LEDGER_CREATE_ERROR;
        }

        // Update the latest seq_no and lcl when ledger is created.
        p2p::sequence_hash new_lcl_id;
        new_lcl_id.seq_no = seq_no;
        new_lcl_id.hash = ledger_hash;
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

        //Remove old shards that exceeds max shard range.
        if (conf::cfg.node.max_shards > 0 && primary_shard_seq_no >= conf::cfg.node.max_shards)
        {
            remove_old_shards(primary_shard_seq_no - conf::cfg.node.max_shards + 1, PRIMARY_DIR);
        }

        sqlite::close_db(&db);
        return ledger_fs.release_rw_session();
    }

    /**
     * Opens a db connection to a shard and populates the shard_seq_no.
     * @param db Database connection to be openned.
     * @param ledger_seq_no Ledger sequence number.
     * @return Returns 0 on success -1 on failure.
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
            if (sqlite::open_db(shard_path + "/" + DATEBASE, db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
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
            if (write(fd, &prev_shard_hash, sizeof(util::h32)) == -1)
            {
                LOG_ERROR << errno << ": Error writing to " << shard_hash_file_path << ".";
                close(fd);
                return -1;
            }
            close(fd);
        }
        else if (sqlite::open_db(shard_path + "/" + DATEBASE, db) == -1)
        {
            LOG_ERROR << errno << ": Error openning the shard database, shard: " << std::to_string(shard_seq_no);
            return -1;
        }

        return 0;
    }

    /**
     * Remove old shards that exceeds max shard range from file system.
     * @param led_shard_no minimum shard number to be in history.
     */
    void remove_old_shards(const uint64_t led_shard_no, std::string_view shard_parent_dir)
    {
        // Remove old shards if full history mode is not enabled.
        if (!conf::cfg.node.full_history)
        {
            const std::string shard_dir_path = ledger_fs.physical_path(hpfs::RW_SESSION_NAME, shard_parent_dir);
            std::list<std::string> shards = util::fetch_dir_entries(shard_dir_path);
            for (const std::string shard : shards)
            {
                uint64_t primary_shard_seq_no;
                util::stoull(shard, primary_shard_seq_no);
                if (primary_shard_seq_no < led_shard_no)
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
     * Save raw data from the consensused proposal. A blob file is only created if there is any user inputs or contract outputs
     * to save disk space.
     * @param ledger_hash Hash of this ledger we are saving.
     * @param candidate_user_inputs Raw inputs received in this consensus round.
     * @param generated_user_outputs Generated raw outputs in this consensus round.
     * @return Returns 0 on success -1 on error.
     */
    int save_ledger_blob(std::string_view ledger_hash, const std::map<std::string, consensus::candidate_user_input> &candidate_user_inputs,
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
            if (write(fd, &prev_shard_hash, sizeof(util::h32)) == -1)
            {
                LOG_ERROR << errno << ": Error writing to " << shard_hash_file_path << ".";
                close(fd);
                return -1;
            }
            close(fd);
        }

        ledger_blob blob;

        blob.ledger_hash = ledger_hash;
        for (const auto &[hash, user_input] : candidate_user_inputs)
        {
            std::string input;
            if (usr::input_store.read_buf(user_input.input, input) != -1)
            {
                const auto itr = blob.inputs.find(user_input.userpubkey);
                if (itr == blob.inputs.end())
                    blob.inputs.emplace(user_input.userpubkey, std::vector<std::string>());
                blob.inputs[user_input.userpubkey].push_back(input);
            }
        }
        for (const auto &[hash, user_output] : generated_user_outputs)
        {
            std::vector<std::string> outputs;
            for (const auto &output : user_output.outputs)
            {
                outputs.push_back(output.message);
            }
            blob.outputs.emplace(user_output.userpubkey, outputs);
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

        if (write(fd, builder.GetBufferPointer(), builder.GetSize()) == -1)
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
        if (last_blob_shard_seq_no >= MAX_BLOB_SHARDS)
        {
            remove_old_shards(last_blob_shard_seq_no - MAX_BLOB_SHARDS + 1, BLOB_DIR);
        }

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
            p2p::sequence_hash lcl_id;
            lcl_id.seq_no = 0;
            // This is the genesis ledger.
            lcl_id.hash = util::h32_empty;
            ctx.set_lcl_id(lcl_id);
        }
        else
        {
            sqlite3 *db = NULL;

            shards.sort([](std::string &a, std::string &b) {
                uint64_t seq_no_a, seq_no_b;
                util::stoull(a, seq_no_a);
                util::stoull(b, seq_no_b);
                return seq_no_a > seq_no_b;
            });

            uint64_t last_primary_shard_seq_no;
            util::stoull(shards.front(), last_primary_shard_seq_no);
            const std::string shard_path = std::string(shard_dir_path).append("/").append(shards.front());

            // Open a database connection.
            if (sqlite::open_db(shard_path + "/" + DATEBASE, &db) == -1)
            {
                LOG_ERROR << errno << ": Error openning the shard database, shard: " << shards.front();
                ledger_fs.release_rw_session();
                return -1;
            }

            sqlite::ledger last_ledger = sqlite::get_last_ledger(db);
            sqlite::close_db(&db);

            p2p::sequence_hash lcl_id;
            lcl_id.seq_no = last_ledger.seq_no;
            lcl_id.hash = util::to_bin(last_ledger.ledger_hash_hex);
            ctx.set_lcl_id(lcl_id);

            ledger_fs.release_rw_session();
        }

        return 0;
    }

    /**
     * Get the hash and shard sequence number of the last shard in the ledger primary directory.
     * @param session_name Hpfs session name.
     * @param last_shard_id Struct which holds last shard data. (sequence number and hash).
     * @param shard_parent_dir Parent director vpath of the shards.
     * @return
    */
    int get_last_shard_info(std::string_view session_name, p2p::sequence_hash &last_shard_id, std::string_view shard_parent_dir)
    {
        const std::string shard_dir_path = ledger_fs.physical_path(session_name, shard_parent_dir);
        std::list<std::string> shards = util::fetch_dir_entries(shard_dir_path);

        if (shards.size() > 0)
        {
            shards.sort([](std::string &a, std::string &b) {
                uint64_t seq_no_a, seq_no_b;
                util::stoull(a, seq_no_a);
                util::stoull(b, seq_no_b);
                return seq_no_a > seq_no_b;
            });

            const std::string shard_path = std::string(shard_parent_dir).append("/").append(shards.front());
            if (ledger_fs.get_hash(last_shard_id.hash, session_name, shard_path) == -1 || util::stoull(shards.front(), last_shard_id.seq_no) == -1)
            {
                LOG_ERROR << "Error reading last shard hash in " << shard_path;
                return -1;
            }
        }
        return 0;
    }
    
} // namespace ledger