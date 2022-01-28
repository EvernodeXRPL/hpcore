#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "util.hpp"

namespace util
{
    constexpr mode_t DIR_PERMS = 0755;

    const std::string to_hex(const std::string_view bin)
    {
        // Allocate the target string.
        std::string encoded_string;
        encoded_string.resize(bin.size() * 2);

        // Get encoded string.
        sodium_bin2hex(
            encoded_string.data(),
            encoded_string.length() + 1, // + 1 because sodium writes ending '\0' character as well.
            reinterpret_cast<const unsigned char *>(bin.data()),
            bin.size());
        return encoded_string;
    }

    const std::string to_bin(const std::string_view hex)
    {
        std::string bin;
        bin.resize(hex.size() / 2);

        const char *hex_end;
        size_t bin_len;
        if (sodium_hex2bin(
                reinterpret_cast<unsigned char *>(bin.data()), bin.size(),
                hex.data(), hex.size(),
                "", &bin_len, &hex_end))
        {
            return ""; // Empty indicates error.
        }

        return bin;
    }

    /**
    * Returns current time in UNIX epoch milliseconds.
    */
    uint64_t get_epoch_milliseconds()
    {
        return std::chrono::duration_cast<std::chrono::duration<std::uint64_t, std::milli>>(
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

    // Provide a safe std::string overload for realpath
    const std::string realpath(const std::string &path)
    {
        std::array<char, PATH_MAX> buffer;
        if (!::realpath(path.c_str(), buffer.data()))
            return {};

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

    /**
     * Clears signal mask and signal handlers from the caller.
     * Called by other processes forked from hpcore threads so they get detatched from
     * the hpcore signal setup.
     */
    void fork_detach()
    {
        // Restore signal handlers to defaults.
        signal(SIGINT, SIG_DFL);
        signal(SIGSEGV, SIG_DFL);
        signal(SIGABRT, SIG_DFL);

        // Remove any signal masks applied by hpcore.
        sigset_t mask;
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);

        // Set process group id (so the terminal doesn't send kill signals to forked children).
        setpgrp();
    }

    // Kill a process with a signal and if specified, wait until it stops running.
    int kill_process(const pid_t pid, const bool wait, const int signal)
    {
        if (kill(pid, signal) == -1)
        {
            LOG_ERROR << errno << ": Error issuing signal to pid " << pid;
            return -1;
        }

        const int wait_options = wait ? 0 : WNOHANG;
        if (waitpid(pid, NULL, wait_options) == -1)
        {
            LOG_ERROR << errno << ": waitpid after kill (pid:" << pid << ") failed.";
            return -1;
        }

        return 0;
    }

    /**
     * Check whether given directory exists. 
     * @param path Directory path.
     * @return Returns true if given directory exists otherwise false.
     */
    bool is_dir_exists(std::string_view path)
    {
        struct stat st;
        return (stat(path.data(), &st) == 0 && S_ISDIR(st.st_mode));
    }

    /**
     * Check whether given file exists. 
     * @param path File path.
     * @return Returns true if give file exists otherwise false.
     */
    bool is_file_exists(std::string_view path)
    {
        struct stat st;
        return (stat(path.data(), &st) == 0 && S_ISREG(st.st_mode));
    }

    /**
     * Recursively creates directories and sub-directories if not exist. 
     * @param path Directory path.
     * @return Returns 0 operations succeeded otherwise -1.
     */
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
            bool error_thrown = false;

            if (create_dir_tree_recursive(parent_dir_path) == -1)
                error_thrown = true;

            free(path2);

            // Create this dir.
            if (!error_thrown && mkdir(path.data(), DIR_PERMS) == -1)
            {
                LOG_ERROR << errno << ": Error in recursive dir creation. " << path;
                error_thrown = true;
            }

            if (error_thrown)
                return -1;
        }

        return 0;
    }

    /**
     * Fetch all the files and directiries inside the given directory. 
     * @param path Directory path.
     * @return Returns the list of entries inside the directory.
     */
    std::list<std::string> fetch_dir_entries(std::string_view path)
    {
        std::list<std::string> entries;
        DIR *dr;

        // Open the directory stream.
        if ((dr = opendir(path.data())))
        {
            // Take next directory entry from the directory stream.
            struct dirent *en;
            while ((en = readdir(dr)))
            {
                // Push into the entries list if reading directory entry is not current directory entry
                // or previous directory entry.
                if (std::strcmp(en->d_name, ".") != 0 && std::strcmp(en->d_name, "..") != 0)
                {
                    entries.push_back(en->d_name);
                }
            }
            // Close directory stream.
            closedir(dr);
        }

        return entries;
    }

    /**
     * Fetch file extension from the file path. 
     * @param path File path.
     * @return Returns the file extension as a string_view.
     */
    std::string_view fetch_file_extension(std::string_view path)
    {
        // Get the position of right most "." in the file path.
        const std::size_t pos = path.rfind('.');

        if (pos != std::string::npos)
        {
            // Take the sub string after the ".".
            return path.substr(pos);
        }

        return "";
    }

    /**
     * Remove file extension from file name. 
     * @param file_name File name.
     * @return Returns the file name without extension.
     */
    std::string_view remove_file_extension(std::string_view file_name)
    {
        // Get the position of right most "." in the file name.
        const std::size_t pos = file_name.rfind('.');

        if (pos != std::string::npos)
        {
            // Take the sub string till the "." from the beginning.
            return file_name.substr(0, pos);
        }

        return file_name;
    }

    /**
     * Deletes a file. 
     * @param path File path.
     * @return Returs 0 if succeed else -1.
     */
    int remove_file(std::string_view path)
    {
        return remove(path.data());
    }

    /**
     * Clears all files from a directory (not recursive).
     */
    int clear_directory(std::string_view dir_path)
    {
        return nftw(
            dir_path.data(), [](const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
            {
                if (typeflag == FTW_F) // Is file.
                    return remove(fpath);
                return 0;
            },
            1, FTW_PHYS);
    }

    /**
     * Remove a directory recursively with it's content. FTW_DEPTH is provided so all of the files and subdirectories within
     * The path will be processed. FTW_PHYS is provided so symbolic links won't be followed.
     */
    int remove_directory_recursively(std::string_view dir_path)
    {
        return nftw(
            dir_path.data(), [](const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
            { return remove(fpath); },
            1, FTW_DEPTH | FTW_PHYS);
    }

    void split_string(std::vector<std::string> &collection, std::string_view str, std::string_view delimeter)
    {
        if (str.empty())
            return;

        size_t start = 0;
        size_t end = str.find(delimeter);

        while (end != std::string::npos)
        {
            // Do not add empty strings.
            if (start != end)
                collection.push_back(std::string(str.substr(start, end - start)));
            start = end + delimeter.length();
            end = str.find(delimeter, start);
        }

        // If there are any leftover from the source string add the remaining.
        if (start < str.size())
            collection.push_back(std::string(str.substr(start)));
    }

    /**
     * Converts given string to a uint_64. A wrapper function for std::stoull. 
     * @param str String variable.
     * @param result Variable to store the answer from the conversion.
     * @return Returns 0 in a successful conversion and -1 on error.
    */
    int stoull(const std::string &str, uint64_t &result)
    {
        try
        {
            result = std::stoull(str);
        }
        catch (const std::exception &e)
        {
            // Return -1 if any exceptions are captured.
            return -1;
        }
        return 0;
    }

    // Returns the file/dir name of the given path.
    const std::string get_name(std::string_view path)
    {
        char *path2 = strdup(path.data());
        const std::string name = basename(path2);
        free(path2);
        return name;
    }

    /**
     * Reads the entire file from given file discriptor. 
     * @param fd File descriptor to be read.
     * @param buf String buffer to be populated.
     * @param offset Begin offset of the file to read.
     * @return Returns number of bytes read in a successful read and -1 on error.
    */
    int read_from_fd(const int fd, std::string &buf, const off_t offset)
    {
        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            LOG_ERROR << errno << ": Error in stat for reading entire file.";
            return -1;
        }

        buf.resize(st.st_size - offset);

        return pread(fd, buf.data(), buf.size(), offset);
    }

    /**
     * Reads the specified portion from the given file descriptor.
     * @param fd File descriptor to be read.
     * @param buf Buffer to populate.
     * @param size How many bytes to read.
     * @param offset Offset position in the file to start reading.
     * @param file_name File name to print in error log.
     * @return 0 on success. -1 on failure or when specified buffer size could not be read.
     */
    int read_from_fd(const int fd, void *buf, const size_t size, const off_t offset, std::string_view file_name)
    {
        const ssize_t res = pread(fd, buf, size, offset);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error when reading " << file_name;
            return -1;
        }
        else if ((size_t)res < size)
        {
            LOG_ERROR << "Not enough bytes read from " << file_name;
            return -1;
        }

        return 0;
    }

    /**
     * Create a record lock for the file descriptor. Lock is associated with the process (Not for forked child processes).
     * @param fd File descriptor to be locked.
     * @param lock File lock.
     * @param is_rwlock Whether the record lock is a write lock.
     * @param start Starting offset for the lock.
     * @param len Number of bytes to lock.
     * @return Returns 0 if lock is successfully acquired, -1 on error.
    */
    int set_lock(const int fd, struct flock &lock, const bool is_rwlock, const off_t start, const off_t len)
    {
        lock.l_type = is_rwlock ? F_WRLCK : F_RDLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = start,
        lock.l_len = len;
        return fcntl(fd, F_SETLK, &lock);
    }

    /**
     * Releases the lock on file descriptor.
     * @param fd File descriptor to be released.
     * @param lock File lock.
     * @return Returns 0 if lock is successfully released, -1 on error.
    */
    int release_lock(const int fd, struct flock &lock)
    {
        lock.l_type = F_UNLCK;
        return fcntl(fd, F_SETLKW, &lock);
    }

    /**
     * Convert the given uint16_t number to bytes in big endian format.
     * @param dest Byte array pointer.
     * @param x Number to be converted.
    */
    void uint16_to_bytes(uint8_t *dest, const uint16_t x)
    {
        dest[0] = (uint8_t)((x >> 8) & 0xff);
        dest[1] = (uint8_t)((x >> 0) & 0xff);
    }

    /**
     * Read the uint16_t number from the given byte array which is in big endian format.
     * @param data Byte array pointer.
     * @return The uint16_t number in the given byte array.
    */
    uint16_t uint16_from_bytes(const uint8_t *data)
    {
        return ((uint16_t)data[0] << 8) +
               (uint16_t)data[1];
    }

    /**
     * Convert the given uint32_t number to bytes in big endian format.
     * @param dest Byte array pointer.
     * @param x Number to be converted.
    */
    void uint32_to_bytes(uint8_t *dest, const uint32_t x)
    {
        dest[0] = (uint8_t)((x >> 24) & 0xff);
        dest[1] = (uint8_t)((x >> 16) & 0xff);
        dest[2] = (uint8_t)((x >> 8) & 0xff);
        dest[3] = (uint8_t)((x >> 0) & 0xff);
    }

    /**
     * Read the uint32_t number from the given byte array which is in big endian format.
     * @param data Byte array pointer.
     * @return The uint32_t number in the given byte array.
    */
    uint32_t uint32_from_bytes(const uint8_t *data)
    {
        return ((uint32_t)data[0] << 24) +
               ((uint32_t)data[1] << 16) +
               ((uint32_t)data[2] << 8) +
               ((uint32_t)data[3]);
    }

    /**
     * Convert the given uint64_t number to bytes in big endian format.
     * @param dest Byte array pointer.
     * @param x Number to be converted.
    */
    void uint64_to_bytes(uint8_t *dest, const uint64_t x)
    {
        dest[0] = (uint8_t)((x >> 56) & 0xff);
        dest[1] = (uint8_t)((x >> 48) & 0xff);
        dest[2] = (uint8_t)((x >> 40) & 0xff);
        dest[3] = (uint8_t)((x >> 32) & 0xff);
        dest[4] = (uint8_t)((x >> 24) & 0xff);
        dest[5] = (uint8_t)((x >> 16) & 0xff);
        dest[6] = (uint8_t)((x >> 8) & 0xff);
        dest[7] = (uint8_t)((x >> 0) & 0xff);
    }

    /**
     * Read the uint64_t number from the given byte array which is in big endian format.
     * @param data Byte array pointer.
     * @return The uint64_t number in the given byte array.
    */
    uint64_t uint64_from_bytes(const uint8_t *data)
    {
        return ((uint64_t)data[0] << 56) +
               ((uint64_t)data[1] << 48) +
               ((uint64_t)data[2] << 40) +
               ((uint64_t)data[3] << 32) +
               ((uint64_t)data[4] << 24) +
               ((uint64_t)data[5] << 16) +
               ((uint64_t)data[6] << 8) +
               ((uint64_t)data[7]);
    }

    /**
     * Returns a string buffer containing uint64 bytes.
     */
    const std::string uint64_to_string_bytes(const uint64_t x)
    {
        std::string s;
        s.resize(sizeof(uint64_t));
        uint64_to_bytes((uint8_t *)s.data(), x);
        return s;
    }

    /**
     * Returns the substring view from the end of the provided string view.
     */
    std::string_view get_string_suffix(std::string_view sv, const size_t suffix_len)
    {
        return sv.substr(sv.size() - suffix_len, suffix_len);
    }

} // namespace util
