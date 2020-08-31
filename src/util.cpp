#include "pchheader.hpp"
#include "hplog.hpp"
#include "util.hpp"

namespace util
{

    // rollover_hashset class methods

    rollover_hashset::rollover_hashset(const uint32_t maxsize)
    {
        this->maxsize = maxsize == 0 ? 1 : maxsize;
    }

    /**
 * Inserts the given hash to the list.
 * @return True on succesful insertion. False if hash already exists.
 */
    bool rollover_hashset::try_emplace(const std::string hash)
    {
        const auto itr = recent_hashes.find(hash);
        if (itr == recent_hashes.end()) // Not found
        {
            // Add the new message hash to the set.
            const auto [newitr, success] = recent_hashes.emplace(std::move(hash));

            // Insert a pointer to the stored hash value to the back of the ordered list of hashes.
            recent_hashes_list.push_back(&(*newitr));

            // Remove oldest hash if exceeding max size.
            if (recent_hashes_list.size() > maxsize)
            {
                const std::string &oldest_hash = *recent_hashes_list.front();
                recent_hashes.erase(oldest_hash);
                recent_hashes_list.pop_front();
            }

            return true; // Hash was inserted successfuly.
        }

        return false; // Hash already exists.
    }

    // ttl_set class methods.

    /**
 * If key does not exist, inserts it with the specified ttl. If key exists,
 * renews the expiration time to match the time-to-live from now onwards.
 * @param key Object to insert.
 * @param ttl Time to live in milliseonds.
 */
    void ttl_set::emplace(const std::string key, uint64_t ttl_milli)
    {
        ttlmap[key] = util::get_epoch_milliseconds() + ttl_milli;
    }

    void ttl_set::erase(const std::string &key)
    {
        const auto itr = ttlmap.find(key);
        if (itr != ttlmap.end())
            ttlmap.erase(itr);
    }

    /**
 * Returns true of the key exists and not expired. Returns false if key does not exist
 * or has expired.
 */
    bool ttl_set::exists(const std::string &key)
    {
        const auto itr = ttlmap.find(key);
        if (itr == ttlmap.end()) // Not found
            return false;

        // Check whether we are passed the expiration time (itr->second is the expiration time)
        const bool expired = util::get_epoch_milliseconds() > itr->second;
        if (expired)
            ttlmap.erase(itr);

        return !expired;
    }

    /**
 * Encodes provided bytes to hex string.
 * 
 * @param encoded_string String reference to assign the hex encoded output.
 * @param bin Bytes to encode.
 * @param bin_len Bytes length.
 * @return Always returns 0.
 */
    int bin2hex(std::string &encoded_string, const unsigned char *bin, const size_t bin_len)
    {
        // Allocate the target string.
        encoded_string.resize(bin_len * 2);

        // Get encoded string.
        sodium_bin2hex(
            encoded_string.data(),
            encoded_string.length() + 1, // + 1 because sodium writes ending '\0' character as well.
            bin,
            bin_len);

        return 0;
    }

    /**
 * Decodes provided hex string into bytes.
 * 
 * @param decodedbuf Buffer to assign decoded bytes.
 * @param decodedbuf_len Decoded buffer size.
 * @param hex_str hex string to decode.
 */
    int hex2bin(unsigned char *decodedbuf, const size_t decodedbuf_len, std::string_view hex_str)
    {
        const char *hex_end;
        size_t bin_len;
        if (sodium_hex2bin(
                decodedbuf, decodedbuf_len,
                hex_str.data(),
                hex_str.length(),
                "", &bin_len, &hex_end))
        {
            return -1;
        }

        return 0;
    }

    std::string get_hex(std::string_view bin, const off_t skip, const size_t take)
    {
        std::string hex;
        const size_t len = (take ? take : (bin.size() - skip));
        bin2hex(hex, reinterpret_cast<unsigned char *>(const_cast<char *>(bin.data() + skip)), len);
        return hex;
    }

    /**
 * Returns current time in UNIX epoch milliseconds.
 */
    int64_t get_epoch_milliseconds()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    /**
 * Sleeps the current thread for specified no. of milliseconds.
 */
    void sleep(const uint64_t milliseconds)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    /**
 * Compare two version strings in the format of "1.12.3".
 * v1 <  v2  -> returns -1
 * v1 == v2  -> returns  0
 * v1 >  v2  -> returns +1
 * Error     -> returns -2
 * 
 * Remark on string_view: In other places of the code-base we utilize string_view
 * to pass immutable string references around. However in this function we keep the 'const string&'
 * syntax because istringstream doesn't support string_view. It's not worth optmising
 * this code as it's not being used in high-scale processing.
 */
    int version_compare(const std::string &x, const std::string &y)
    {
        std::istringstream ix(x), iy(y);
        while (ix.good() || iy.good())
        {
            int cx = 0, cy = 0;
            ix >> cx;
            iy >> cy;

            if ((!ix.eof() && !ix.good()) || (!iy.eof() && !iy.good()))
                return -2;

            if (cx > cy)
                return 1;
            if (cx < cy)
                return -1;

            ix.ignore();
            iy.ignore();
        }

        return 0;
    }

    // Provide a safe std::string overload for realpath
    std::string realpath(std::string path)
    {
        std::array<char, PATH_MAX> buffer;
        ::realpath(path.c_str(), buffer.data());
        buffer[PATH_MAX] = '\0';
        return buffer.data();
    }

    // Applies signal mask to the calling thread.
    void mask_signal()
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
    }

    // Clears signal mask from the calling thread.
    // Used for other processes forked from hpcore threads.
    void unmask_signal()
    {
        sigset_t mask;
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);
    }

    // Kill a process with a signal and wait until it stops running.
    int kill_process(const pid_t pid, const bool wait, int signal)
    {
        if (kill(pid, signal) == -1)
        {
            LOG_ERR << errno << ": Error issuing signal to pid " << pid;
            return -1;
        }

        int pid_status;
        if (wait && waitpid(pid, &pid_status, 0) == -1)
        {
            LOG_ERR << errno << ": waitpid after kill failed.";
            return -1;
        }

        return 0;
    }

    bool is_dir_exists(std::string_view path)
    {
        struct stat st;
        return (stat(path.data(), &st) == 0 && S_ISDIR(st.st_mode));
    }

    int create_dir_tree_recursive(std::string_view path)
    {
        if (strcmp(path.data(), "/") == 0) // No need of checking if we are at root.
            return 0;

        // Check whether this dir exists or not.
        struct stat st;
        if (stat(path.data(), &st) != 0 || !S_ISDIR(st.st_mode))
        {
            // Check and create parent dir tree first.
            char *path2 = strdup(path.data());
            char *parent_dir_path = dirname(path2);
            if (create_dir_tree_recursive(parent_dir_path) == -1)
                return -1;

            // Create this dir.
            if (mkdir(path.data(), S_IRWXU | S_IRWXG | S_IROTH) == -1)
                return -1;
        }

        return 0;
    }

} // namespace util
