#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "hasher.hpp"
#include "state_restore.hpp"
#include "hashtree_builder.hpp"
#include "state_common.hpp"

namespace statefs
{

// Look at new files added and delete them if still exist.
void state_restore::delete_new_files()
{
    std::string index_file(ctx.delta_dir);
    index_file.append(IDX_NEW_FILES);

    std::ifstream in_file(index_file);
    for (std::string file; std::getline(in_file, file);)
    {
        std::string filepath(ctx.data_dir);
        filepath.append(file);

        remove(filepath.c_str());
    }

    in_file.close();
}

// Look at touched files and restore them.
int state_restore::restore_touched_files()
{
    std::unordered_set<std::string> processed;

    std::string index_file(ctx.delta_dir);
    index_file.append(IDX_TOUCHED_FILES);

    std::ifstream in_file(index_file);
    for (std::string file; std::getline(in_file, file);)
    {
        // Skip if already processed.
        if (processed.count(file) > 0)
            continue;

        std::vector<char> bindex;
        if (read_block_index(bindex, file) != 0)
            return -1;

        if (restore_blocks(file, bindex) != 0)
            return -1;

        // Add to processed file list.
        processed.emplace(file);
    }

    in_file.close();
    return 0;
}

// Read the delta block index.
int state_restore::read_block_index(std::vector<char> &buffer, std::string_view file)
{
    std::string bindex_file(ctx.delta_dir);
    bindex_file.append(file).append(BLOCK_INDEX_EXT);
    std::ifstream in_file(bindex_file, std::ios::binary | std::ios::ate);
    std::streamsize idx_size = in_file.tellg();
    in_file.seekg(0, std::ios::beg);

    buffer.resize(idx_size);
    if (!in_file.read(buffer.data(), idx_size))
    {
        LOG_ERR << errno << ": Read failed " << bindex_file;
        return -1;
    }

    return 0;
}

// Restore blocks mentioned in the delta block index.
int state_restore::restore_blocks(std::string_view file, const std::vector<char> &bindex)
{
    int bcache_fd = 0, ori_file_fd = 0;
    const char *idx_ptr = bindex.data();

    // First 8 bytes of the index contains the supposed length of the original file.
    off_t original_len = 0;
    memcpy(&original_len, idx_ptr, 8);

    // Open block cache file.
    {
        std::string bcache_file(ctx.delta_dir);
        bcache_file.append(file).append(BLOCK_CACHE_EXT);
        bcache_fd = open(bcache_file.c_str(), O_RDONLY);
        if (bcache_fd <= 0)
        {
            LOG_ERR << errno << ": Open failed " << bcache_file;
            return -1;
        }
    }

    // Create or Open original file.
    {
        std::string original_file(ctx.data_dir);
        original_file.append(file);

        // Create directory tree if not exist so we are able to create the file.
        boost::filesystem::path filedir = boost::filesystem::path(original_file).parent_path();
        if (created_dirs.count(filedir.string()) == 0)
        {
            boost::filesystem::create_directories(filedir);
            created_dirs.emplace(filedir.string());
        }

        ori_file_fd = open(original_file.c_str(), O_WRONLY | O_CREAT, FILE_PERMS);
        if (ori_file_fd <= 0)
        {
            LOG_ERR << errno << ": Open failed " << original_file;
            return -1;
        }
    }

    // Restore the blocks as specified in block index.
    for (uint32_t idx_offset = 8; idx_offset < bindex.size();)
    {
        // Find the block no. of where this block is from in the original file.
        uint32_t block_no = 0;
        memcpy(&block_no, idx_ptr + idx_offset, 4);
        idx_offset += 4;
        off_t ori_file_offset = block_no * BLOCK_SIZE;

        // Find the offset where the block is located in the block cache file.
        off_t bcache_offset;
        memcpy(&bcache_offset, idx_ptr + idx_offset, 8);
        idx_offset += 40; // Skip the hash(32)

        // Transfer the cached block to the target file.
        copy_file_range(bcache_fd, &bcache_offset, ori_file_fd, &ori_file_offset, BLOCK_SIZE, 0);
    }

    // If the target file is bigger than the original size, truncate it to the original size.
    off_t current_len = lseek(ori_file_fd, 0, SEEK_END);
    if (current_len > original_len)
        ftruncate(ori_file_fd, original_len);

    close(bcache_fd);
    close(ori_file_fd);

    return 0;
}

// This is called after a rollback so the all checkpoint dirs shift by 1.
void state_restore::rewind_checkpoints()
{
    // Assuming we have restored the current state with current delta,
    // we need to shift each history delta by 1 place.

    // Delete the state 0 (current) delta.
    boost::filesystem::remove_all(ctx.delta_dir);

    int16_t oldest_chkpnt = (MAX_CHECKPOINTS + 1) * -1; // +1 because we maintain one extra checkpoint in case of rollbacks.
    for (int16_t chkpnt = -1; chkpnt >= oldest_chkpnt; chkpnt--)
    {
        std::string dir = get_state_dir_root(chkpnt);

        if (boost::filesystem::exists(dir))
        {
            if (chkpnt == -1)
            {
                // Shift -1 state delta dir to 0-state and delete -1 dir.
                std::string delta_1 = dir + DELTA_DIR;
                boost::filesystem::rename(delta_1, ctx.delta_dir);
                boost::filesystem::remove_all(dir);
            }
            else
            {
                std::string dirshift = get_state_dir_root(chkpnt + 1);
                boost::filesystem::rename(dir, dirshift);
            }
        }
    }
}

// Rolls back current state to previous state.
int state_restore::rollback(hasher::B2H &root_hash)
{
    ctx = get_state_dir_context();

    delete_new_files();
    if (restore_touched_files() == -1)
        return -1;

    // Update hash tree.
    hashtree_builder htree_builder(ctx);
    htree_builder.generate(root_hash);

    rewind_checkpoints();

    return 0;
}

} // namespace statefs