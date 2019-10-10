#include <string>
#include <sodium.h>
#include <sstream>

using namespace std;

namespace util
{

/**
 * Encodes provided bytes to base64 string.
 * 
 * @param bin Bytes to encode.
 * @param bin_len Bytes length.
 * @param encoded_string String reference to assign the base64 encoded output.
 */
int base64_encode(const unsigned char *bin, size_t bin_len, string &encoded_string)
{
    // Get length of encoded result from sodium.
    const size_t base64_len = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char base64chars[base64_len];

    // Get encoded string.
    const char *encoded_str_char = sodium_bin2base64(
        base64chars, base64_len,
        bin, bin_len,
        sodium_base64_VARIANT_ORIGINAL);

    if (encoded_str_char == NULL)
        return -1;

    // Assign the encoded char* onto the provided string reference.
    // "base64_len - 1" because sodium include '\0' in the calculated base64 length.
    //      Therefore we need to omit it when initializing the std::string.
    encoded_string = string(base64chars, base64_len - 1);
    return 0;
}

/**
 * Decodes provided base64 string into bytes.
 * 
 * @param base64_str Base64 string to decode.
 * @param decoded Decoded bytes.
 * @param decoded_len Decoded bytes length.
 */
int base64_decode(const string &base64_str, unsigned char *decoded, size_t decoded_len)
{
    const char *b64_end;
    size_t bin_len;
    if (sodium_base642bin(
            decoded, decoded_len,
            base64_str.data(), base64_str.size() + 1,
            "", &bin_len, &b64_end,
            sodium_base64_VARIANT_ORIGINAL))
    {
        return -1;
    }

    return 0;
}

/**
 * Compare two version strings in the format of "1.12.3".
 * v1 <  v2  -> returns -1
 * v1 == v2  -> returns  0
 * v1 >  v2  -> returns +1
 * Error     -> returns -2
 */
int version_compare(const string &x, const string &y)
{
    istringstream ix(x), iy(y);
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

} // namespace util