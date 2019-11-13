#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../proc/proc.hpp"

namespace cons
{

constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; //this is the logical block size files are decomposed in, it's also the size of the merkle tree
constexpr size_t HASH_SIZE = crypto_generichash_blake2b_BYTES;
constexpr size_t MAX_HASHES = BLOCK_SIZE / HASH_SIZE;
constexpr const char *MERKLE_EXTENSION = ".merkle";

struct B2H // blake2b hash is 32 bytes which we store as 4 quad words
{
    uint64_t data[4];
};

// provide some helper functions for working with 32 byte hash type
bool operator==(B2H &lhs, B2H &rhs)
{
    return lhs.data[0] == rhs.data[0] && lhs.data[1] == rhs.data[1] && lhs.data[2] == rhs.data[2] && lhs.data[3] == rhs.data[3];
}

// the actual hash function, note that the B2H datatype is always passed by value being only 4 quadwords
B2H hash(const void *ptr, size_t len)
{
    B2H ret;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, HASH_SIZE);
    crypto_generichash_blake2b_update(&state,
                                      reinterpret_cast<const unsigned char *>(ptr), len);
    crypto_generichash_blake2b_final(
        &state,
        reinterpret_cast<unsigned char *>(&ret),
        HASH_SIZE);
    return ret;
}

/**
 * Updates the .merkel block map for the given state file.
 * @param filepath Full path of the state file.
 * @param hinted_blocks Set of updated file block ids. If empty full merkel block map will be recomputed.
 */
int update_file_blockmap(const std::string &filepath, const std::set<uint32_t> &hinted_blocks)
{
    // .merkel file path will be corresponding path in "statemap" directory.
    std::string merkle_fn;
    const size_t relative_path_len = filepath.length() - conf::ctx.statedir.length();
    merkle_fn.reserve(conf::ctx.statemapdir.length() + relative_path_len + 7);
    merkle_fn.append(conf::ctx.statemapdir);
    merkle_fn.append(filepath.substr(conf::ctx.statedir.length(), relative_path_len));
    merkle_fn.append(MERKLE_EXTENSION);

    // To benefit from hint mode, the .merkle file must already exist. If not we simply disable hint mode
    // because we anyway have to rebuild entire merkle file from scratch.
    bool hint_mode = !hinted_blocks.empty();
    if (access(merkle_fn.c_str(), F_OK) == -1)
        hint_mode = false;

    // open the target file for which we are building or updating a merkle tree
    FILE *f = fopen(filepath.c_str(), "rb");
    if (!f)
    {
        LOG_ERR << "Failed to open state file: " << filepath << " for reading.";
        return -1;
    }

    // the merkle tree structure is only 4mb and could technically sit on stack in most cases but
    // TODO: ******Why can't we allocate this on the stack?
    auto merkle_tree = std::make_unique<B2H[]>(MAX_HASHES);
    // same with the read buffer
    auto read_buffer = std::make_unique<uint8_t[]>(BLOCK_SIZE);

    // this iterator will be used if we are in hint mode
    auto hint = hinted_blocks.begin();

    size_t block_counter = 0;
    size_t block_location = 0;

    while (true)
    {
        // if hint blocks have been specified we'll seek to specific blocks in the file based on hint list.
        if (hint_mode)
        {
            // check if we've run out of elements
            if (hint == hinted_blocks.end())
                break;

            // get the next block on their list
            block_location = *hint++;

            // seek the file cursor to the block
            fseek(f, block_location * BLOCK_SIZE, SEEK_SET);
        }

        // read the block
        int bytesread = fread(read_buffer.get(), 1, BLOCK_SIZE, f);
        if (bytesread <= 0)
            break;

        // calculate the block hash
        merkle_tree[block_location++] = hash(read_buffer.get(), std::min(BLOCK_SIZE, (size_t)bytesread));
        block_counter++;
    }

    fclose(f);

    // now that we've computed all the block hashes we are interested in we have to deal with the .merkle file

    // open the .merkle file
    // if we are in hint_mode we will open it in rb+ which will preserve its contents
    // otherwise we will truncate it if it already exists, because we will have to overwrite everything anyway
    FILE *fm = fopen(merkle_fn.c_str(), (hint_mode ? "rb+" : "wb+"));
    if (!fm)
    {
        LOG_ERR << "Failed to open merkle file: " << filepath << " for writing.";
        return -1;
    }

    // get the size of the .merkle file
    fseek(fm, 0L, SEEK_END);
    const size_t len = ftell(fm);
    rewind(fm);

    // write the updated hashes
    if (hint_mode)
    {
        // write selectively the updated block hashes
        const int fd = fileno(fm);
        for (int block : hinted_blocks)
            pwrite(fd, &(merkle_tree[block]), HASH_SIZE, HASH_SIZE * block);
    }
    else
    {
        // write the whole tree to the file
        fwrite(reinterpret_cast<void *>(merkle_tree.get()), 1, std::min(BLOCK_SIZE, HASH_SIZE * block_counter), fm);
    }

    // compute the root hash

    B2H root_hash;

    if (hint_mode)
    {
        // if we only updated selective hashes (hint mode) then now we need to compute a hash over the whole merkle file
        // so we first need to read it in
        rewind(f);
        int bytesread = fread(read_buffer.get(), 1, BLOCK_SIZE, f);
        if (bytesread <= 0)
            fprintf(stderr, "could not read merkle file after writing to it?!\n");

        // now simply compute the hash of what we just read, that's our root hash
        root_hash = hash(read_buffer.get(), std::min(BLOCK_SIZE, (size_t)bytesread));
    }
    else
    {
        // if we've just written out the whole merkle tree we already know it
        root_hash = hash(merkle_tree.get(), std::min(BLOCK_SIZE, HASH_SIZE * block_counter));
    }

    fclose(fm);
}

/**
 * Updates the state block map for the files updated as specified by the provided blockmap.
 * TODO: This doesn't currently support deleted file tracking.
 */
void update_state_blockmap(const proc::contract_fblockmap_t &updates)
{
    for (const auto &[filepath, blocks] : updates)
    {
        update_file_blockmap(filepath, blocks);
    }
}

} // namespace cons