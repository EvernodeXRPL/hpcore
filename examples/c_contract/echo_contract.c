#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract

void echo_contract(const struct hotpocket_contract_context *ctx);
void on_user_message(const struct hotpocket_user *user, const void *buf, const uint32_t len);
void on_peer_message(const char *peerPubKey, const void *buf, const uint32_t len);

int main(int argc, char **argv)
{
    if (hotpocket_init(echo_contract) == -1)
        return 1;

    return 0;
}

void echo_contract(const struct hotpocket_contract_context *ctx)
{
    // hotpocket_peer_message_listener(ctx, on_peer_message);

    hotpocket_user_message_loop(ctx, on_user_message);
}

void on_user_message(const struct hotpocket_user *user, const void *buf, const uint32_t len)
{
    struct iovec vec[2] = {{"Echoing: ", 9}, {(void *)buf, len}};
    hotpocket_user_writev(user, vec, 2);
}

void on_peer_message(const char *peerPubKey, const void *buf, const uint32_t len)
{
}
