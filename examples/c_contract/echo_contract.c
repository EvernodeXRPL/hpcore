#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract -pthread -lm

void echo_contract(const struct hp_contract_context *ctx);
void on_user_message(const struct hp_contract_context *ctx, const struct hp_user *user, const void *buf, const uint32_t len);
void on_peer_message(const struct hp_contract_context *ctx, const char *peerPubKey, const void *buf, const uint32_t len);

int main(int argc, char **argv)
{
    if (hp_init(echo_contract) == -1)
        return 1;

    return 0;
}

/**
 * HP smart contract is defined as a function which takes HP contract context as an argument.
 * HP considers execution as complete, when this function returns.
 */
void echo_contract(const struct hp_contract_context *ctx)
{
    // Non-blocking call. This will start the peer message (NPL) listener.
    // hp_peer_message_listener(ctx, on_peer_message);

    // Peer message sending example.
    // hp_peer_write(ctx, "Hello", 5);

    if (!ctx->readonly)
    {
        // We just save execution timestamp as an example state file change.
        int fd = open("exects.txt", O_RDWR | O_CREAT | O_APPEND);
        if (fd > 0)
        {
            char tsbuf[20];
            sprintf(tsbuf, "%lu\n", ctx->timestamp);
            struct iovec vec[2] = {{"ts:", 4}, {(void *)tsbuf, 20}};
            writev(fd, vec, 2);
            close(fd);
        }
    }

    // Blocking call. This will block until all user messages are looped.
    hp_user_message_loop(ctx, on_user_message);
}

void on_user_message(const struct hp_contract_context *ctx, const struct hp_user *user, const void *buf, const uint32_t len)
{
    if (strncmp(buf, "ts", 2) == 0)
    {
        int fd = open("exects.txt", O_RDONLY);
        if (fd > 0)
        {
            struct stat st;
            if (fstat(fd, &st) != -1)
            {
                char tsbuf[st.st_size];
                if (read(fd, tsbuf, st.st_size) > 0)
                {
                    hp_user_write(user, tsbuf, st.st_size);
                }
            }
            close(fd);
        }
    }
    else
    {
        struct iovec vec[2] = {{"Echoing: ", 9}, {(void *)buf, len}};
        hp_user_writev(user, vec, 2);
    }
}

// Peer message handler func.
// void on_peer_message(const struct hp_contract_context *ctx, const char *peerPubKey, const void *buf, const uint32_t len)
// {
// }
