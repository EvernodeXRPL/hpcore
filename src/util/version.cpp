#include "version.hpp"
#include "util.hpp"

namespace version
{
    // Binary representations of the versions. (populated during version init)
    uint8_t HP_VERSION_BYTES[VERSION_BYTES_LEN];
    uint8_t LEDGER_VERSION_BYTES[VERSION_BYTES_LEN];

    int init()
    {
        // Generate version bytes.
        if (set_version_bytes(HP_VERSION_BYTES, HP_VERSION) == -1 ||
            set_version_bytes(LEDGER_VERSION_BYTES, LEDGER_VERSION) == -1)
            return -1;

        return 0;
    }

    /**
     * Create 8 byte binary version from version string. First 6 bytes contains the 3 version components and the 
     * next 2 bytes are reserved for future use.
     * @param bytes Byte buffer to be populated with binary version data.
     * @param version Version string.
     * @return Returns -1 on error and 0 on success.
    */
    int set_version_bytes(uint8_t *bytes, std::string_view version)
    {
        memset(bytes, 0, VERSION_BYTES_LEN);

        const std::string delimeter = ".";
        size_t start = 0;
        size_t end = version.find(delimeter);

        if (end == std::string::npos)
        {
            std::cerr << "Invalid version " << version << std::endl;
            return -1;
        }

        const uint16_t major = atoi(version.substr(start, end - start).data());

        start = end + delimeter.length();
        end = version.find(delimeter, start);

        if (end == std::string::npos)
        {
            std::cerr << "Invalid version " << version << std::endl;
            return -1;
        }

        const uint16_t minor = atoi(version.substr(start, end - start).data());
        start = end + delimeter.length();
        end = version.find(delimeter, start);

        const uint16_t patch = atoi(version.substr(start).data());

        util::uint16_to_bytes(&bytes[0], major);
        util::uint16_to_bytes(&bytes[2], minor);
        util::uint16_to_bytes(&bytes[4], patch);

        return 0;
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
     * syntax because istringstream doesn't support string_view. It's not worth optimising
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
}