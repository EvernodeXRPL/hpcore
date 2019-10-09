#include <string>
#include <sodium.h>

using namespace std;

namespace shared
{

void replace_string_contents(string &str, const char *bytes, size_t bytes_len);

int base64_encode(unsigned char *bin, size_t bin_len, string &encoded_string)
{
    const size_t base64_len = sodium_base64_encoded_len(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char base64chars[base64_len];

    char *encoded_str_char = sodium_bin2base64(
        base64chars, base64_len,
        bin, bin_len,
        sodium_base64_VARIANT_ORIGINAL);

    if (encoded_str_char == NULL)
        return -1;

    replace_string_contents(encoded_string, base64chars, base64_len);
    return 0;
}

int base64_decode(string &base64_str, unsigned char *decoded, size_t decoded_len)
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

void replace_string_contents(string &str, const char *bytes, size_t bytes_len)
{
    if (str.length() > 0)
        str.clear();
    str.append(bytes, bytes_len);
}

//   v1 <  v2  -> -1
//   v1 == v2  ->  0
//   v1 >  v2  -> +1
int version_compare(string &v1, string &v2)
{
    size_t i = 0, j = 0;
    while (i < v1.length() || j < v2.length())
    {
        int acc1 = 0, acc2 = 0;

        while (i < v1.length() && v1[i] != '.')
        {
            acc1 = acc1 * 10 + (v1[i] - '0');
            i++;
        }
        while (j < v2.length() && v2[j] != '.')
        {
            acc2 = acc2 * 10 + (v2[j] - '0');
            j++;
        }

        if (acc1 < acc2)
            return -1;
        if (acc1 > acc2)
            return +1;

        ++i;
        ++j;
    }
    return 0;
}

} // namespace shared