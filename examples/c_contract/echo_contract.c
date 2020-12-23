#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract

void store_timestamp(const uint64_t timestamp);
void process_user_message(const struct hp_user *user, const void *buf, const uint32_t len);

int main(int argc, char **argv)
{
    if (hp_init_contract() == -1)
        return 1;

    const struct hp_contract_context *ctx = hp_get_context();

    // We store the execution timestamp as an example state file change.
    if (!ctx->readonly)
        store_timestamp(ctx->timestamp);

    // Read and process all user inputs from the mmap.
    const void *input_mmap = hp_init_user_input_mmap();

    // Iterate through all users.
    for (int u = 0; u < ctx->users.count; u++)
    {
        const struct hp_user *user = &ctx->users.list[u];

        // Iterate through all inputs from this user.
        for (int i = 0; i < user->inputs.count; i++)
        {
            const struct hp_user_input input = user->inputs.list[i];

            // Instead of mmap, we can also read the inputs from 'ctx->users.in_fd' using file I/O.
            // However, using mmap is recommended because user inputs already reside in memory.
            const void *buf = input_mmap + input.offset;

            process_user_message(user, buf, input.size);
        }
    }

    // Peer message send example:
    // hp_write_peer_msg("Hello!", 6);

    // Peer message receive example:
    // // Allocate buffers for received message.
    // char sender[HP_KEY_SIZE];
    // char *msg = malloc(HP_PEER_MSG_MAX_SIZE);
    // // Wait for 200ms for incoming message. We will receive our own message as well.
    // const int len = hp_read_peer_msg(msg, sender, 200);
    // if (len > 0)
    //     printf("Received %.*s from %.*s", len, msg, HP_KEY_SIZE, sender);
    // free(msg);

    // Update UNL example:
    // hp_update_unl("<66 char hex to add>", 1, "<66 char hex to remove>", 1);

    hp_deinit_user_input_mmap();
    hp_deinit_contract();
    return 0;
}

void store_timestamp(const uint64_t timestamp)
{
    int fd = open("exects.txt", O_RDWR | O_CREAT | O_APPEND);
    if (fd > 0)
    {
        char tsbuf[20];
        memset(tsbuf, 0, 20);
        sprintf(tsbuf, "%lu\n", timestamp);
        struct iovec vec[2] = {{"ts:", 4}, {(void *)tsbuf, 20}};
        writev(fd, vec, 2);
        close(fd);
    }
}

void process_user_message(const struct hp_user *user, const void *buf, const uint32_t len)
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
                    for (int i = 0; i < st.st_size; i++)
                    {
                        if (tsbuf[i] == '\n' || tsbuf[i] == 0)
                            tsbuf[i] = ' ';
                    }
                    hp_write_user_msg(user, tsbuf, st.st_size - 1);
                }
            }
            close(fd);
        }
    }
    else
    {
        struct iovec vec[2] = {{"Echoing: ", 9}, {(void *)buf, len}};
        hp_writev_user_msg(user, vec, 2);
    }
}
