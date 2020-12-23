#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "util.hpp"

namespace util
{
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
    const std::string realpath(const std::string &path)
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
            if (!error_thrown && mkdir(path.data(), S_IRWXU | S_IRWXG | S_IROTH) == -1)
                error_thrown = true;

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
        if (dr = opendir(path.data()))
        {
            // Take next directory entry from the directory stream.
            struct dirent *en;
            while (en = readdir(dr))
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
            dir_path.data(), [](const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
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
            dir_path.data(), [](const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
                return remove(fpath);
            },
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

} // namespace util
