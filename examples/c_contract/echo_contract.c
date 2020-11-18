#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract && ./echo_contract

void echo_contract(const struct hotpocket_context *ctx);
void on_user_message(const struct hotpocket_user *user, const void *buf, const uint32_t len);
void on_peer_message(const char *peerPubKey, const void *buf, const uint32_t len);

int main(int argc, char **argv)
{
    if (hotpocket_init(echo_contract) == -1)
        return 1;

    return 0;
}

void echo_contract(const struct hotpocket_context *ctx)
{
    hotpocket_run(ctx, on_user_message, on_peer_message);
}

void on_user_message(const struct hotpocket_user *user, const void *buf, const uint32_t len)
{
    printf("rcvd %*s from %s\n", len, (char *)buf, user->pubkey);
}

void on_peer_message(const char *peerPubKey, const void *buf, const uint32_t len)
{
}
