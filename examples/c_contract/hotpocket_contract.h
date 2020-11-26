#ifndef HOTPOCKET_CONTRACT_LIB
#define HOTPOCKET_CONTRACT_LIB

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <pthread.h>
#include "json.h"

#define __HP_KEY_SIZE 64
#define __HP_HASH_SIZE 64
#define __HP_MSG_HEADER_LEN 4
#define __HP_SEQPKT_BUF_SIZE 131072 // 128KB to support SEQ_PACKET sockets.
#define __HP_POLL_TIMEOUT 20

#define __HP_MMAP_BLOCK_SIZE 4096
#define __HP_MMAP_BLOCK_ALIGN(x) (((x) + ((typeof(x))(__HP_MMAP_BLOCK_SIZE)-1)) & ~((typeof(x))(__HP_MMAP_BLOCK_SIZE)-1))

#define __HP_ASSIGN_STRING(dest, elem)                                                    \
    if (elem->value->type == json_type_string)                                            \
    {                                                                                     \
        const struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
        memcpy(dest, value->string, sizeof(dest));                                        \
    }

#define __HP_ASSIGN_UINT64(dest, elem)                                                    \
    if (elem->value->type == json_type_number)                                            \
    {                                                                                     \
        const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = strtoull(value->number, NULL, 0);                                          \
    }

#define __HP_ASSIGN_INT(dest, elem)                                                       \
    if (elem->value->type == json_type_number)                                            \
    {                                                                                     \
        const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = atoi(value->number);                                                       \
    }

#define __HP_ASSIGN_BOOL(dest, elem)               \
    if (elem->value->type == json_type_true)       \
        dest = true;                               \
    else if (elem->value->type == json_type_false) \
        dest = false;

#define __HP_FROM_BE(buf, pos) \
    ((uint8_t)buf[pos + 0] << 24 | (uint8_t)buf[pos + 1] << 16 | (uint8_t)buf[pos + 2] << 8 | (uint8_t)buf[pos + 3])

#define __HP_TO_BE(num, buf, pos) \
    buf[pos] = num >> 24;         \
    buf[1 + pos] = num >> 16;     \
    buf[2 + pos] = num >> 8;      \
    buf[3 + pos] = num;

struct hp_user_input
{
    off_t offset;
    uint32_t size;
};

struct hp_user
{
    char pubkey[__HP_KEY_SIZE + 1];
    int outfd;
    struct hp_user_input *inputs;
    uint32_t inputs_count;
};

struct hp_peer
{
    char pubkey[__HP_KEY_SIZE + 1];
};

struct hp_users_collection
{
    int infd;
    struct hp_user *list;
    size_t count;
};

struct hp_peers_collection
{
    struct hp_peer *list;
    size_t count;
    int fd;
};

struct hp_contract_context
{
    bool readonly;

    uint64_t timestamp;
    char pubkey[__HP_KEY_SIZE + 1];

    char lcl_hash[__HP_HASH_SIZE + 1];
    uint64_t lcl_seq_no;

    struct hp_users_collection users;
    struct hp_peers_collection peers;
};

struct __hp_global_context
{
    int control_fd;
    bool should_stop;
};

typedef void (*hp_contract_func)(const struct hp_contract_context *ctx);
typedef void (*hp_user_message_func)(const struct hp_contract_context *ctx,
                                     const struct hp_user *user, const void *buf, const uint32_t len);
typedef void (*hp_peer_message_func)(const struct hp_contract_context *ctx,
                                     const char *peerPubKey, const void *buf, const uint32_t len);

struct __hp_peer_message_thread_arg
{
    const struct hp_contract_context *ctx;
    hp_peer_message_func on_peer_message;
};

int hp_init();
int hp_user_message_loop(const struct hp_contract_context *ctx, hp_user_message_func on_user_message);
int hp_peer_message_listener(const struct hp_contract_context *ctx, hp_peer_message_func on_peer_message);

int hp_user_write(const struct hp_user *user, const uint8_t *buf, const uint32_t len);
int hp_user_writev(const struct hp_user *user, const struct iovec *bufs, const int buf_count);

int hp_peer_write(const struct hp_contract_context *ctx, const uint8_t *buf, const uint32_t len);
int hp_peer_writev(const struct hp_contract_context *ctx, const struct iovec *bufs, const int buf_count);

void __hp_parse_args_json(struct __hp_global_context *gctx, struct hp_contract_context *ctx, const struct json_object_s *object);
void __hp_free_contract_context(struct hp_contract_context *ctx);

static void *__hp_peer_message_thread_func(void *arg);

static void *__hp_control_message_thread_func(void *arg);
void __hp_on_control_message(const void *buf, const uint32_t len);

static struct __hp_global_context gctx = {};
static pthread_t __hp_control_thread = 0;
static pthread_t __hp_peer_thread = 0;

int hp_init(hp_contract_func contract_func)
{
    if (!contract_func)
        return -1;

    char buf[4096];
    const size_t len = read(STDIN_FILENO, buf, sizeof(buf));
    if (len == -1)
        return -1;

    struct json_value_s *root = json_parse(buf, len);

    if (root && root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        if (object->length > 0)
        {
            // Create and populate hotpocket context.
            struct hp_contract_context ctx = {};
            __hp_parse_args_json(&gctx, &ctx, object);
            free(root);

            // Start control channel listener.
            if (pthread_create(&__hp_control_thread, NULL, &__hp_control_message_thread_func, NULL) == -1)
            {
                perror("Error creating control thread");
                goto error;
            }

            // Execute user defined contract function.
            if (contract_func)
                contract_func(&ctx);

            // Instructs to all threads to gracefully stop.
            gctx.should_stop = true;

            if (__hp_peer_thread)
                pthread_join(__hp_peer_thread, NULL);
            __hp_peer_thread = 0;

            pthread_join(__hp_control_thread, NULL);
            __hp_control_thread = 0;

            // Cleanup.
            close(ctx.users.infd);
            for (int i = 0; i < ctx.users.count; i++)
                close(ctx.users.list[i].outfd);

            close(ctx.peers.fd);

            __hp_free_contract_context(&ctx);

            // Send termination control message.
            write(gctx.control_fd, "{\"type\":\"contract_end\"}", 10);
            close(gctx.control_fd);
            return 0;
        }
    }

error:

    if (root)
        free(root);

    return -1;
}

int hp_user_message_loop(const struct hp_contract_context *ctx, hp_user_message_func on_user_message)
{
    int result = 0;
    const int fd = ctx->users.infd;

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("Error in user input fd stat");
        return -1;
    }

    if (st.st_size == 0)
        return 0;

    const size_t mmap_size = __HP_MMAP_BLOCK_ALIGN(st.st_size);
    void *fdptr = mmap(NULL, mmap_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdptr == MAP_FAILED)
    {
        perror("Error in user input fd mmap");
        return -1;
    }

    close(fd); // We can close the fd after mmap.

    for (int i = 0; i < ctx->users.count; i++)
    {
        const struct hp_user *user = &ctx->users.list[i];
        for (int j = 0; j < user->inputs_count; j++)
        {
            const struct hp_user_input *input = &user->inputs[j];
            on_user_message(ctx, user, (fdptr + input->offset), input->size);
        }
    }

    munmap(fdptr, mmap_size);
}

int hp_peer_message_listener(const struct hp_contract_context *ctx, hp_peer_message_func on_peer_message)
{
    if (__hp_peer_thread)
    {
        fprintf(stderr, "Peer listener already started.\n");
        return -1;
    }

    // We need to malloc the arg so it doesn't go out of scope. (It will be freed by the thread func when it exits)
    struct __hp_peer_message_thread_arg *arg = malloc(sizeof(struct __hp_peer_message_thread_arg));
    arg->ctx = ctx;
    arg->on_peer_message = on_peer_message;
    if (pthread_create(&__hp_peer_thread, NULL, &__hp_peer_message_thread_func, arg) == -1)
    {
        perror("Error creating peer thread");
        return -1;
    }

    return 0;
}

int hp_user_write(const struct hp_user *user, const uint8_t *buf, const uint32_t len)
{
    const struct iovec vec = {(void *)buf, len};
    return hp_user_writev(user, &vec, 1);
}

int hp_user_writev(const struct hp_user *user, const struct iovec *bufs, const int buf_count)
{
    const int total_buf_count = buf_count + 1;
    struct iovec all_bufs[total_buf_count]; // We need to prepend the length header buf to indicate user message length.

    uint32_t msg_len = 0;
    for (int i = 0; i < buf_count; i++)
    {
        all_bufs[i + 1].iov_base = bufs[i].iov_base;
        all_bufs[i + 1].iov_len = bufs[i].iov_len;
        msg_len += bufs[i].iov_len;
    }

    uint8_t header_buf[__HP_MSG_HEADER_LEN];
    __HP_TO_BE(msg_len, header_buf, 0);

    all_bufs[0].iov_base = header_buf;
    all_bufs[0].iov_len = __HP_MSG_HEADER_LEN;

    return writev(user->outfd, all_bufs, total_buf_count);
}

int hp_peer_write(const struct hp_contract_context *ctx, const uint8_t *buf, const uint32_t len)
{
    if (len > __HP_SEQPKT_BUF_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", __HP_SEQPKT_BUF_SIZE);
        return -1;
    }

    return write(ctx->peers.fd, buf, len);
}

int hp_peer_writev(const struct hp_contract_context *ctx, const struct iovec *bufs, const int buf_count)
{
    uint32_t len = 0;
    for (int i = 0; i < buf_count; i++)
        len += bufs[i].iov_len;

    if (len > __HP_SEQPKT_BUF_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", __HP_SEQPKT_BUF_SIZE);
        return -1;
    }

    return writev(ctx->peers.fd, bufs, buf_count);
}

void __hp_parse_args_json(struct __hp_global_context *gctx, struct hp_contract_context *ctx, const struct json_object_s *object)
{
    const struct json_object_element_s *elem = object->start;
    do
    {
        const struct json_string_s *k = elem->name;

        if (strcmp(k->string, "pubkey") == 0)
        {
            __HP_ASSIGN_STRING(ctx->pubkey, elem);
        }
        else if (strcmp(k->string, "ts") == 0)
        {
            __HP_ASSIGN_UINT64(ctx->timestamp, elem);
        }
        else if (strcmp(k->string, "readonly") == 0)
        {
            __HP_ASSIGN_BOOL(ctx->readonly, elem);
        }
        else if (strcmp(k->string, "lcl") == 0)
        {
            if (elem->value->type == json_type_string)
            {
                const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
                const char *delim = "-";
                char *tok_ptr;
                char *tok_str = strdup(value->string);
                const char *seq_str = strtok_r(tok_str, delim, &tok_ptr);
                const char *hash_str = strtok_r(NULL, delim, &tok_ptr);

                ctx->lcl_seq_no = strtoull(seq_str, NULL, 0);
                memcpy(ctx->lcl_hash, hash_str, __HP_HASH_SIZE);
                free(tok_str);
            }
        }
        else if (strcmp(k->string, "userinfd") == 0)
        {
            __HP_ASSIGN_INT(ctx->users.infd, elem);
        }
        else if (strcmp(k->string, "users") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                const struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                ctx->users.count = user_count;
                ctx->users.list = user_count ? (struct hp_user *)malloc(sizeof(struct hp_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (int i = 0; i < user_count; i++)
                    {
                        struct hp_user *user = &ctx->users.list[i];
                        memcpy(user->pubkey, user_elem->name->string, __HP_KEY_SIZE);

                        if (user_elem->value->type == json_type_array)
                        {
                            const struct json_array_s *arr = (struct json_array_s *)user_elem->value->payload;
                            struct json_array_element_s *arr_elem = arr->start;

                            // First element is the output fd.
                            __HP_ASSIGN_INT(user->outfd, arr_elem);
                            arr_elem = arr_elem->next;

                            // Subsequent elements are tupels of [offset, size] of input messages for this user.
                            user->inputs_count = arr->length - 1;
                            user->inputs = user->inputs_count ? malloc(user->inputs_count * sizeof(struct hp_user_input)) : NULL;
                            for (int i = 0; i < user->inputs_count; i++)
                            {
                                if (arr_elem->value->type == json_type_array)
                                {
                                    const struct json_array_s *input_info = (struct json_array_s *)arr_elem->value->payload;
                                    if (input_info->length == 2)
                                    {
                                        __HP_ASSIGN_UINT64(user->inputs[i].offset, input_info->start);
                                        __HP_ASSIGN_UINT64(user->inputs[i].size, input_info->start->next);
                                    }
                                }
                                arr_elem = arr_elem->next;
                            }
                        }
                        user_elem = user_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "nplfd") == 0)
        {
            __HP_ASSIGN_INT(ctx->peers.fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                const struct json_array_s *peer_array = (struct json_array_s *)elem->value->payload;
                const size_t peer_count = peer_array->length;

                ctx->peers.count = peer_count;
                ctx->peers.list = peer_count ? (struct hp_peer *)malloc(sizeof(struct hp_peer) * peer_count) : NULL;

                if (peer_count > 0)
                {
                    struct json_array_element_s *peer_elem = peer_array->start;
                    for (int i = 0; i < peer_count; i++)
                    {
                        __HP_ASSIGN_STRING(ctx->peers.list[i].pubkey, peer_elem);
                        peer_elem = peer_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "hpfd") == 0)
        {
            __HP_ASSIGN_INT(gctx->control_fd, elem);
        }

        elem = elem->next;
    } while (elem);
}

static void *__hp_peer_message_thread_func(void *arg)
{
    const struct __hp_peer_message_thread_arg *args = (const struct __hp_peer_message_thread_arg *)arg;

    // Pubkey buf to hold the sender pubkey of the message that follows it.
    bool has_pubkey = false;
    char pubkey_buf[__HP_KEY_SIZE + 1];
    memset(pubkey_buf, 0, sizeof(pubkey_buf));

    // Buffer to hold current message.
    uint8_t *msg_buf = malloc(__HP_SEQPKT_BUF_SIZE);

    struct pollfd pfd = {args->ctx->peers.fd, POLLIN, 0};

    while (!gctx.should_stop)
    {
        // Reset poll fd because we are reusing it.
        pfd.revents = 0;

        if (poll(&pfd, 1, __HP_POLL_TIMEOUT) == -1)
        {
            perror("Peer channel poll error");
            goto error;
        }

        short result = pfd.revents;
        if (result == 0)
            continue;

        if (result & (POLLHUP | POLLERR | POLLNVAL))
        {
            fprintf(stderr, "Peer channel poll returned error.\n");
            goto error;
        }
        else if (result & POLLIN)
        {
            // The read data alternates between the sender pubkey and the message.
            if (!has_pubkey)
            {
                if (read(pfd.fd, pubkey_buf, __HP_KEY_SIZE) == -1)
                {
                    perror("Error reading pubkey from peer channel");
                    goto error;
                }
                has_pubkey = true;
            }
            else
            {
                const size_t read_res = read(pfd.fd, msg_buf, __HP_SEQPKT_BUF_SIZE);
                if (read_res == -1)
                {
                    perror("Error reading message from peer channel");
                    goto error;
                }

                // Invoke the user defined peer message handler func.
                args->on_peer_message(args->ctx, pubkey_buf, msg_buf, read_res);
                has_pubkey = false;
            }
        }
    }

    // If we reach here that means result is successful.
    goto end;

error:
    // Perform any error handling.

end:
    free(arg);
    free(msg_buf);
    return NULL;
}

static void *__hp_control_message_thread_func(void *arg)
{
    int result = 0;

    // Temp buffer for all read operations.
    uint8_t *buf = malloc(__HP_SEQPKT_BUF_SIZE);

    struct pollfd pfd = {gctx.control_fd, POLLIN, 0};

    while (!gctx.should_stop)
    {
        // Reset poll fd because we are reusing it.
        pfd.revents = 0;

        if (poll(&pfd, 1, __HP_POLL_TIMEOUT) == -1)
        {
            perror("Control channel poll error");
            goto error;
        }

        short result = pfd.revents;
        if (result == 0)
            continue;

        if (result & (POLLHUP | POLLERR | POLLNVAL))
        {
            fprintf(stderr, "Control channel poll returned error.\n");
            goto error;
        }
        else if (result & POLLIN)
        {
            const size_t read_res = read(pfd.fd, buf, __HP_SEQPKT_BUF_SIZE);
            if (read_res == -1)
            {
                perror("Error reading control channel");
                goto error;
            }

            __hp_on_control_message(buf, read_res);
        }
    }

    // If we reach here that means result is successful.
    goto end;

error:
    // Perform any error handling.

end:
    free(buf);
    return NULL;
}

void __hp_on_control_message(const void *buf, const uint32_t len)
{
    // TODO: Handle control messages from hot pocket.
}

void __hp_free_contract_context(struct hp_contract_context *ctx)
{
    if (ctx->users.list)
    {
        for (int i = 0; i < ctx->users.count; i++)
        {
            if (ctx->users.list[i].inputs)
                free(ctx->users.list[i].inputs);
        }
        free(ctx->users.list);
    }

    if (ctx->peers.list)
        free(ctx->peers.list);
}

#endif