#ifndef HOTPOCKET_CONTRACT_LIB
#define HOTPOCKET_CONTRACT_LIB

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/uio.h>
#include <pthread.h>
#include "json.h"

#define _HP_KEY_SIZE 64
#define _HP_HASH_SIZE 64
#define _HP_MSG_HEADER_LEN 4
#define _HP_USER_BUF_SIZE 4096     // Buffer used to read user message data.
#define _HP_SEQPKT_BUF_SIZE 131072 // 128KB to support SEQ_PACKET sockets.
#define _HP_POLL_TIMEOUT 20

#define _HP_MIN(a, b) ((a < b) ? a : b)

#define _HP_ASSIGN_STRING(dest, elem)                                       \
    if (elem->value->type == json_type_string)                                      \
    {                                                                               \
        struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
        memcpy(dest, value->string, sizeof(dest));                                  \
    }

#define _HP_ASSIGN_UINT64(dest, elem)                                       \
    if (elem->value->type == json_type_number)                                      \
    {                                                                               \
        struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = strtoull(value->number, NULL, 0);                                    \
    }

#define _HP_ASSIGN_INT(dest, elem)                                          \
    if (elem->value->type == json_type_number)                                      \
    {                                                                               \
        struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = atoi(value->number);                                                 \
    }

#define _HP_ASSIGN_BOOL(dest, elem)        \
    if (elem->value->type == json_type_true)       \
        dest = true;                               \
    else if (elem->value->type == json_type_false) \
        dest = false;

#define _HP_FROM_BE(buf, pos) \
    ((uint8_t)buf[pos + 0] << 24 | (uint8_t)buf[pos + 1] << 16 | (uint8_t)buf[pos + 2] << 8 | (uint8_t)buf[pos + 3])

#define _HP_TO_BE(num, buf, pos) \
    buf[pos] = num >> 24;                \
    buf[1 + pos] = num >> 16;            \
    buf[2 + pos] = num >> 8;             \
    buf[3 + pos] = num;

struct hp_user
{
    char pubkey[_HP_KEY_SIZE + 1];
    int fd;
};

struct hp_peer
{
    char pubkey[_HP_KEY_SIZE + 1];
};

struct hp_users_collection
{
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
    char pubkey[_HP_KEY_SIZE + 1];

    char lcl_hash[_HP_HASH_SIZE + 1];
    uint64_t lcl_seq_no;

    struct hp_users_collection users;
    struct hp_peers_collection peers;
};

struct __hp_global_context
{
    int control_fd;
    bool should_stop;
};

struct __hp_user_state
{
    bool completed; // Whether we have finished processing all incoming messages for this user.

    uint32_t total_messages;     // Total messages for the user.
    uint32_t processed_messages; // No. of processed messages so far for the user.
    bool total_messages_known;   // Whether the total messages count has been set properly.

    uint8_t header_buf[_HP_MSG_HEADER_LEN]; // Header length buf (total msg count or msg size header).
    uint8_t header_filled_len;                      // Current no. of header bytes collected so far.

    uint32_t msg_actual_len; // Actual(final) size of current message.
    uint32_t msg_filled_len; // Current no. of message bytes collected so far.
    uint8_t *msg_buf;        // Buf holding the collected bytes for the current message.

    struct hp_user *user; // The user reference tracked by this state struct.
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

void __hp_parse_user_chunk(const struct hp_contract_context *ctx, struct __hp_user_state *us,
                                  const uint8_t *buf, const uint32_t len, hp_user_message_func on_user_message);
bool __hp_parse_length_header(struct __hp_user_state *us, const uint8_t *chunk, const uint32_t chunk_len,
                                     uint32_t *chunk_pos, uint32_t *target);

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
                perror("Error creating control thread. ");
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
            for (int i = 0; i < ctx.users.count; i++)
                close(ctx.users.list[i].fd);

            close(ctx.peers.fd);

            // Send termination control message.
            write(gctx.control_fd, "Terminated", 10);
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

    // We poll user fds, control fd and npl fd (npl fd not available in read only mode)
    const size_t total_users = ctx->users.count;
    size_t remaining_users = total_users;

    // User states list to keep track of message collection status for each user.
    struct __hp_user_state user_states[total_users];
    memset(user_states, 0, sizeof(struct __hp_user_state) * total_users);

    // Temp buffer for all read operations.
    uint8_t *buf = malloc(_HP_USER_BUF_SIZE);

    // Create fd set to be polled.
    struct pollfd pollfds[total_users];
    for (int i = 0; i < total_users; i++)
    {
        pollfds[i].fd = ctx->users.list[i].fd;
        pollfds[i].events = POLLIN;
        pollfds[i].revents = 0;

        user_states[i].user = &ctx->users.list[i];
    }

    while (remaining_users > 0)
    {
        // Reset poll fd set because we are reusing it.
        for (int i = 0; i < total_users; i++)
            pollfds[0].revents = 0;

        if (poll(pollfds, total_users, _HP_POLL_TIMEOUT) == -1)
        {
            perror("User poll error. ");
            goto error;
        }

        for (int i = 0; i < total_users; i++)
        {
            short result = pollfds[i].revents;
            if (result == 0)
                continue;

            if (result & (POLLHUP | POLLERR | POLLNVAL))
            {
                fprintf(stderr, "User poll returned error.\n");
                goto error;
            }
            else if (result & POLLIN)
            {
                const size_t read_res = read(pollfds[i].fd, buf, _HP_USER_BUF_SIZE);
                if (read_res == -1)
                {
                    perror("Error reading user socket. ");
                    goto error;
                }

                if (!user_states[i].completed)
                {
                    // User sockets are stream sockets. So we have to do the message stitching ourselves based on
                    // total msg count and msg size headers sent over the stream.
                    __hp_parse_user_chunk(ctx, &user_states[i], buf, read_res, on_user_message);

                    if (user_states[i].completed)
                    {
                        remaining_users--;

                        // All users completed.
                        if (remaining_users == 0)
                            break;
                    }
                }
            }
        }
    }

    // If we reach here that means result is successful.
    result = 0;
    goto end;

error:
    // On error set result to -1.
    result = -1;

end:
    for (int i = 0; i < total_users; i++)
    {
        if (user_states[i].msg_buf)
            free(user_states[i].msg_buf);
    }

    free(buf);
    return result;
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
        perror("Error creating peer thread. ");
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

    uint8_t header_buf[_HP_MSG_HEADER_LEN];
    _HP_TO_BE(msg_len, header_buf, 0);

    all_bufs[0].iov_base = header_buf;
    all_bufs[0].iov_len = _HP_MSG_HEADER_LEN;

    return writev(user->fd, all_bufs, total_buf_count);
}

int hp_peer_write(const struct hp_contract_context *ctx, const uint8_t *buf, const uint32_t len)
{
    if (len > _HP_SEQPKT_BUF_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", _HP_SEQPKT_BUF_SIZE);
        return -1;
    }

    return write(ctx->peers.fd, buf, len);
}

int hp_peer_writev(const struct hp_contract_context *ctx, const struct iovec *bufs, const int buf_count)
{
    uint32_t len = 0;
    for (int i = 0; i < buf_count; i++)
        len += bufs[i].iov_len;

    if (len > _HP_SEQPKT_BUF_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", _HP_SEQPKT_BUF_SIZE);
        return -1;
    }

    return writev(ctx->peers.fd, bufs, buf_count);
}

void __hp_parse_user_chunk(const struct hp_contract_context *ctx, struct __hp_user_state *us,
                                  const uint8_t *chunk, const uint32_t chunk_len, hp_user_message_func on_user_message)
{
    uint32_t pos = 0;

    if (!us->total_messages_known)
        us->total_messages_known = __hp_parse_length_header(us, chunk, chunk_len, &pos, &us->total_messages);

    if (!us->total_messages_known)
        return;

    if (us->total_messages == 0)
    {
        us->completed = true;
        return;
    }

    while (pos < chunk_len)
    {
        if (us->msg_actual_len == 0)
        {
            if (__hp_parse_length_header(us, chunk, chunk_len, &pos, &us->msg_actual_len) && us->msg_actual_len == 0)
            {
                // If we parse msg length=0, then abandon further processing for this user.
                fprintf(stderr, "Message size 0 received for user.\n");
                us->completed = true;
                return;
            }
        }

        // Going inside following 'if' means we know the current message length, and there are more data bytes to be read.
        if (us->msg_actual_len > 0 && pos < chunk_len)
        {
            if (!us->msg_buf)
                us->msg_buf = malloc(us->msg_actual_len);

            const uint32_t remaining_len = chunk_len - pos;
            const uint32_t msg_bytes_to_copy = _HP_MIN(remaining_len, (us->msg_actual_len - us->msg_filled_len));

            memcpy(us->msg_buf + us->msg_filled_len, (chunk + pos), msg_bytes_to_copy);
            us->msg_filled_len += msg_bytes_to_copy;
            pos += msg_bytes_to_copy;

            // See whether we just completed forming a full message.
            if (us->msg_filled_len == us->msg_actual_len)
            {
                // Execute on_message func with msg_buf.
                on_user_message(ctx, us->user, us->msg_buf, us->msg_actual_len);

                // Reset message construction.
                free(us->msg_buf);
                us->msg_buf = NULL;
                us->msg_actual_len = 0;
                us->msg_filled_len = 0;
                us->processed_messages++;

                if (us->processed_messages == us->total_messages)
                {
                    us->completed = true;
                    return;
                }
            }
        }
    }
}

bool __hp_parse_length_header(struct __hp_user_state *us, const uint8_t *chunk, const uint32_t chunk_len,
                                     uint32_t *chunk_pos, uint32_t *target)
{
    uint32_t pos = *chunk_pos;
    const uint32_t remaining_len = chunk_len - pos;

    // See if we can detect complete length header without the help of the header buffer.
    if (remaining_len >= _HP_MSG_HEADER_LEN && us->header_filled_len == 0)
    {
        *target = _HP_FROM_BE(chunk, pos);
        *chunk_pos = pos + _HP_MSG_HEADER_LEN;
        return true;
    }
    else
    {
        const uint32_t header_bytes_to_copy = _HP_MIN(remaining_len, (_HP_MSG_HEADER_LEN - us->header_filled_len));

        memcpy(us->header_buf + us->header_filled_len, (chunk + pos), header_bytes_to_copy);
        us->header_filled_len += header_bytes_to_copy;
        *chunk_pos = pos + header_bytes_to_copy;

        // See whether we can now read length value after new bytes where added to the header.
        if (us->header_filled_len == _HP_MSG_HEADER_LEN)
        {
            *target = _HP_FROM_BE(us->header_buf, 0);
            us->header_filled_len = 0;
            return true;
        }
    }

    return false; // Couldn't detect the length header with available bytes.
}

void __hp_parse_args_json(struct __hp_global_context *gctx, struct hp_contract_context *ctx, const struct json_object_s *object)
{
    struct json_object_element_s *elem = object->start;
    do
    {
        struct json_string_s *k = elem->name;

        if (strcmp(k->string, "pubkey") == 0)
        {
            _HP_ASSIGN_STRING(ctx->pubkey, elem);
        }
        else if (strcmp(k->string, "ts") == 0)
        {
            _HP_ASSIGN_UINT64(ctx->timestamp, elem);
        }
        else if (strcmp(k->string, "readonly") == 0)
        {
            _HP_ASSIGN_BOOL(ctx->readonly, elem);
        }
        else if (strcmp(k->string, "lcl") == 0)
        {
            if (elem->value->type == json_type_string)
            {
                struct json_string_s *value = (struct json_string_s *)elem->value->payload;
                const char *delim = "-";
                char *tok_ptr;
                char *tok_str = strdup(value->string);
                const char *seq_str = strtok_r(tok_str, delim, &tok_ptr);
                const char *hash_str = strtok_r(NULL, delim, &tok_ptr);

                ctx->lcl_seq_no = strtoull(seq_str, NULL, 0);
                memcpy(ctx->lcl_hash, hash_str, _HP_HASH_SIZE);
            }
        }
        else if (strcmp(k->string, "usrfd") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                ctx->users.count = user_count;
                ctx->users.list = user_count ? (struct hp_user *)malloc(sizeof(struct hp_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (int i = 0; i < user_count; i++)
                    {
                        memcpy(ctx->users.list[i].pubkey, user_elem->name->string, _HP_KEY_SIZE);
                        _HP_ASSIGN_INT(ctx->users.list[i].fd, user_elem);

                        user_elem = user_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "nplfd") == 0)
        {
            _HP_ASSIGN_INT(ctx->peers.fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                struct json_array_s *peer_array = (struct json_array_s *)elem->value->payload;
                const size_t peer_count = peer_array->length;

                ctx->peers.count = peer_count;
                ctx->peers.list = peer_count ? (struct hp_peer *)malloc(sizeof(struct hp_peer) * peer_count) : NULL;

                if (peer_count > 0)
                {
                    struct json_array_element_s *peer_elem = peer_array->start;
                    for (int i = 0; i < peer_count; i++)
                    {
                        _HP_ASSIGN_STRING(ctx->peers.list[i].pubkey, peer_elem);
                        peer_elem = peer_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "hpfd") == 0)
        {
            _HP_ASSIGN_INT(gctx->control_fd, elem);
        }

        elem = elem->next;
    } while (elem);
}

static void *__hp_peer_message_thread_func(void *arg)
{
    const struct __hp_peer_message_thread_arg *args = (const struct __hp_peer_message_thread_arg *)arg;

    // Pubkey buf to hold the sender pubkey of the message that follows it.
    bool has_pubkey = false;
    char pubkey_buf[_HP_KEY_SIZE + 1];
    memset(pubkey_buf, 0, sizeof(pubkey_buf));

    // Buffer to hold current message.
    uint8_t *msg_buf = malloc(_HP_SEQPKT_BUF_SIZE);

    struct pollfd pfd = {args->ctx->peers.fd, POLLIN, 0};

    while (!gctx.should_stop)
    {
        // Reset poll fd because we are reusing it.
        pfd.revents = 0;

        if (poll(&pfd, 1, _HP_POLL_TIMEOUT) == -1)
        {
            perror("Peer channel poll error. ");
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
                if (read(pfd.fd, pubkey_buf, _HP_KEY_SIZE) == -1)
                {
                    perror("Error reading pubkey from peer channel. ");
                    goto error;
                }
                has_pubkey = true;
            }
            else
            {
                const size_t read_res = read(pfd.fd, msg_buf, _HP_USER_BUF_SIZE);
                if (read_res == -1)
                {
                    perror("Error reading message from peer channel. ");
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
    uint8_t *buf = malloc(_HP_SEQPKT_BUF_SIZE);

    struct pollfd pfd = {gctx.control_fd, POLLIN, 0};

    while (!gctx.should_stop)
    {
        // Reset poll fd because we are reusing it.
        pfd.revents = 0;

        if (poll(&pfd, 1, _HP_POLL_TIMEOUT) == -1)
        {
            perror("Control channel poll error. ");
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
            const size_t read_res = read(pfd.fd, buf, _HP_USER_BUF_SIZE);
            if (read_res == -1)
            {
                perror("Error reading control channel. ");
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

#endif