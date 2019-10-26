#include <string>
#include <sodium.h>
#include <sstream>
#include <chrono>
#include <rapidjson/document.h>

namespace util
{

/**
 * Encodes provided bytes to hex string.
 * 
 * @param encoded_string String reference to assign the hex encoded output.
 * @param bin Bytes to encode.
 * @param bin_len Bytes length.
 * @return Always returns 0.
 */
int bin2hex(std::string &encoded_string, const unsigned char *bin, size_t bin_len)
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
int hex2bin(unsigned char *decodedbuf, size_t decodedbuf_len, std::string_view hex_str)
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

/**
 * Returns a std::string_view pointing to the rapidjson Value which is assumed
 * to be a string. We use this function because rapidjson does not have build-in string_view
 * support. Passing a non-string 'v' is not supported.
 */
std::string_view getsv(const rapidjson::Value &v)
{
    return std::string_view(v.GetString(), v.GetStringLength());
}

} // namespace util