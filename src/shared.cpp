#include <string>
#include <sodium.h>

using namespace std;

namespace shared
{

string base64_encode(unsigned char *bin, size_t bin_len)
{
    const size_t base64_max_len = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char base64_str[base64_max_len];

    char *encoded_str_char = sodium_bin2base64(
        base64_str, base64_max_len,
        bin, bin_len,
        sodium_base64_VARIANT_ORIGINAL);

    if (encoded_str_char == NULL)
        throw "Base64 Error: Failed to encode string";

    string s(base64_str);
    return s;
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
        return 0;
    }

    return 1;
}

}