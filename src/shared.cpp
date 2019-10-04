#include <string>
#include <sodium.h>

using namespace std;

namespace shared
{

int base64_encode(unsigned char *bin, size_t bin_len, string &encoded_string)
{
    const size_t base64_max_len = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char base64_str[base64_max_len];

    char *encoded_str_char = sodium_bin2base64(
        base64_str, base64_max_len,
        bin, bin_len,
        sodium_base64_VARIANT_ORIGINAL);

    if (encoded_str_char == NULL)
        return -1;

    encoded_string.clear();
    encoded_string.append(base64_str, base64_max_len);
    return 0;
}

int base64_decode(string base64_str, unsigned char *decoded, size_t decoded_len)
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

} // namespace shared