#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

using namespace std;

namespace crypto
{

int init();
unsigned long long get_sig_len();
void sign(const unsigned char *msg, unsigned long long msg_len, unsigned char *sig, const unsigned char *seckey);
bool verify(const unsigned char *msg, unsigned long long msg_len, const unsigned char *sig, const unsigned char *pubkey);

} // namespace crypto

#endif