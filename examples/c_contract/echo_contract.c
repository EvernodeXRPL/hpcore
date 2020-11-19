#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract -pthread

void echo_contract(const struct hotpocket_contract_context *ctx);
void on_user_message(const struct hotpocket_contract_context *ctx, const struct hotpocket_user *user, const void *buf, const uint32_t len);
void on_peer_message(const struct hotpocket_contract_context *ctx, const char *peerPubKey, const void *buf, const uint32_t len);

int main(int argc, char **argv)
{
    if (hotpocket_init(echo_contract) == -1)
        return 1;

    return 0;
}

/**
 * HP smart contract is defined as a function which takes HP contract context as an argument.
 * HP considers execution as complete, when this function returns.
 */
void echo_contract(const struct hotpocket_contract_context *ctx)
{
    // Non-blocking call. This will start the peer message (NPL) listener.
    // hotpocket_peer_message_listener(ctx, on_peer_message);

    // Peer message sending example.
    // hotpocket_peer_write(ctx, "Hello", 5);

    // Blocking call. This will block until all user messages are looped.
    hotpocket_user_message_loop(ctx, on_user_message);
}

void on_user_message(const struct hotpocket_contract_context *ctx, const struct hotpocket_user *user, const void *buf, const uint32_t len)
{
    struct iovec vec[2] = {{"Echoing: ", 9}, {(void *)buf, len}};
    hotpocket_user_writev(user, vec, 2);
}

// Peer message handler func.
// void on_peer_message(const struct hotpocket_contract_context *ctx, const char *peerPubKey, const void *buf, const uint32_t len)
// {
// }
