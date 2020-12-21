#ifndef __HOTPOCKET_CONTRACT_LIB_C__
#define __HOTPOCKET_CONTRACT_LIB_C__

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "json.h"

#define __HP_MMAP_BLOCK_SIZE 4096
#define __HP_MMAP_BLOCK_ALIGN(x) (((x) + ((off_t)(__HP_MMAP_BLOCK_SIZE)-1)) & ~((off_t)(__HP_MMAP_BLOCK_SIZE)-1))
#define __HP_STREAM_MSG_HEADER_SIZE 4
#define __HP_SEQPKT_MAX_SIZE 131072 // 128KB to support SEQ_PACKET sockets.
#define HP_PEER_MSG_MAX_SIZE __HP_SEQPKT_MAX_SIZE
#define HP_KEY_SIZE 64
#define HP_HASH_SIZE 64

#define __HP_ASSIGN_STRING(dest, elem)                                                        \
    {                                                                                         \
        if (elem->value->type == json_type_string)                                            \
        {                                                                                     \
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
            memcpy(dest, value->string, sizeof(dest));                                        \
        }                                                                                     \
    }

#define __HP_ASSIGN_UINT64(dest, elem)                                                        \
    {                                                                                         \
        if (elem->value->type == json_type_number)                                            \
        {                                                                                     \
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
            dest = strtoull(value->number, NULL, 0);                                          \
        }                                                                                     \
    }

#define __HP_ASSIGN_INT(dest, elem)                                                           \
    {                                                                                         \
        if (elem->value->type == json_type_number)                                            \
        {                                                                                     \
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
            dest = atoi(value->number);                                                       \
        }                                                                                     \
    }

#define __HP_ASSIGN_BOOL(dest, elem)                   \
    {                                                  \
        if (elem->value->type == json_type_true)       \
            dest = true;                               \
        else if (elem->value->type == json_type_false) \
            dest = false;                              \
    }

#define __HP_FROM_BE(buf, pos) \
    ((uint8_t)buf[pos + 0] << 24 | (uint8_t)buf[pos + 1] << 16 | (uint8_t)buf[pos + 2] << 8 | (uint8_t)buf[pos + 3])

#define __HP_TO_BE(num, buf, pos) \
    {                             \
        buf[pos] = num >> 24;     \
        buf[1 + pos] = num >> 16; \
        buf[2 + pos] = num >> 8;  \
        buf[3 + pos] = num;       \
    }

struct hp_user_input
{
    off_t offset;
    uint32_t size;
};

struct hp_user_inputs_collection
{
    struct hp_user_input *list;
    size_t count;
};

struct hp_user
{
    char pubkey[HP_KEY_SIZE + 1];
    int outfd;
    struct hp_user_inputs_collection inputs;
};

struct hp_peer
{
    char pubkey[HP_KEY_SIZE + 1];
};

struct hp_users_collection
{
    struct hp_user *list;
    size_t count;
    int in_fd;
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
    char pubkey[HP_KEY_SIZE + 1];
    char lcl[HP_HASH_SIZE + 22]; // uint64(20 chars) + "-" + hash + nullchar
    struct hp_users_collection users;
    struct hp_peers_collection peers;
};

struct __hp_contract
{
    struct hp_contract_context *cctx;
    int control_fd;
    void *user_inmap;
    size_t user_inmap_size;
};

int hp_init_contract();
int hp_deinit_contract();
const struct hp_contract_context *hp_get_context();
const void *hp_init_user_input_mmap();
void hp_deinit_user_input_mmap();
int hp_write_user_msg(const struct hp_user *user, const void *buf, const uint32_t len);
int hp_writev_user_msg(const struct hp_user *user, const struct iovec *bufs, const int buf_count);
int hp_write_peer_msg(const void *buf, const uint32_t len);
int hp_writev_peer_msg(const struct iovec *bufs, const int buf_count);
int hp_read_peer_msg(void *msg_buf, char *pubkey_buf, const int timeout);
int hp_update_unl(const char *add, const size_t add_count, const char *remove, const size_t remove_count);

void __hp_parse_args_json(const struct json_object_s *object);
int __hp_write_control_msg(const void *buf, const uint32_t len);
void __hp_free(void *ptr);

static struct __hp_contract __hpc = {};

int hp_init_contract()
{
    if (__hpc.cctx)
        return -1; // Already initialized.

    // Check whether we are running from terminal and produce warning.
    if (isatty(STDIN_FILENO) == 1)
    {
        fprintf(stderr, "Error: Hot Pocket smart contracts must be executed via Hot Pocket.\n");
        return -1;
    }

    char buf[4096];
    const size_t len = read(STDIN_FILENO, buf, sizeof(buf));
    if (len == -1)
    {
        perror("Error when reading stdin.");
        return -1;
    }

    struct json_value_s *root = json_parse(buf, len);

    if (root && root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        if (object->length > 0)
        {
            // Create and populate hotpocket context.
            __hpc.cctx = (struct hp_contract_context *)malloc(sizeof(struct hp_contract_context));
            __hp_parse_args_json(object);
            __hp_free(root);

            return 0;
        }
    }

    __hp_free(root);
    return -1;
}

int hp_deinit_contract()
{
    struct hp_contract_context *cctx = __hpc.cctx;

    if (!cctx)
        return -1; // Not initialized.

    // Cleanup user input mmap (if mapped).
    hp_deinit_user_input_mmap();

    // Cleanup user and peer fds.
    close(cctx->users.in_fd);
    for (int i = 0; i < cctx->users.count; i++)
        close(cctx->users.list[i].outfd);
    close(cctx->peers.fd);

    // Cleanup user list allocation.
    if (cctx->users.list)
    {
        for (int i = 0; i < cctx->users.count; i++)
            __hp_free(cctx->users.list[i].inputs.list);

        __hp_free(cctx->users.list);
    }
    // Cleanup peer list allocation.
    __hp_free(cctx->peers.list);
    // Cleanup contract context.
    __hp_free(cctx);

    // Send termination control message.
    __hp_write_control_msg("{\"type\":\"contract_end\"}", 23);
    close(__hpc.control_fd);
}

const struct hp_contract_context *hp_get_context()
{
    return __hpc.cctx;
}

const void *hp_init_user_input_mmap()
{
    if (__hpc.user_inmap)
        return __hpc.user_inmap;

    struct hp_contract_context *cctx = __hpc.cctx;
    struct stat st;
    if (fstat(cctx->users.in_fd, &st) == -1)
    {
        perror("Error in user input fd stat");
        return NULL;
    }

    if (st.st_size == 0)
        return NULL;

    const size_t mmap_size = __HP_MMAP_BLOCK_ALIGN(st.st_size);
    void *mmap_ptr = mmap(NULL, mmap_size, PROT_READ, MAP_PRIVATE, cctx->users.in_fd, 0);
    if (mmap_ptr == MAP_FAILED)
    {
        perror("Error in user input fd mmap");
        return NULL;
    }

    __hpc.user_inmap = mmap_ptr;
    __hpc.user_inmap_size = mmap_size;
    return __hpc.user_inmap;
}

void hp_deinit_user_input_mmap()
{
    if (__hpc.user_inmap)
        munmap(__hpc.user_inmap, __hpc.user_inmap_size);
    __hpc.user_inmap = NULL;
    __hpc.user_inmap_size = 0;
}

int hp_write_user_msg(const struct hp_user *user, const void *buf, const uint32_t len)
{
    const struct iovec vec = {(void *)buf, len};
    return hp_writev_user_msg(user, &vec, 1);
}

int hp_writev_user_msg(const struct hp_user *user, const struct iovec *bufs, const int buf_count)
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

    uint8_t header_buf[__HP_STREAM_MSG_HEADER_SIZE];
    __HP_TO_BE(msg_len, header_buf, 0);

    all_bufs[0].iov_base = header_buf;
    all_bufs[0].iov_len = __HP_STREAM_MSG_HEADER_SIZE;

    return writev(user->outfd, all_bufs, total_buf_count);
}

int hp_write_peer_msg(const void *buf, const uint32_t len)
{
    if (len > HP_PEER_MSG_MAX_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", HP_PEER_MSG_MAX_SIZE);
        return -1;
    }

    return write(__hpc.cctx->peers.fd, buf, len);
}

int hp_writev_peer_msg(const struct iovec *bufs, const int buf_count)
{
    uint32_t len = 0;
    for (int i = 0; i < buf_count; i++)
        len += bufs[i].iov_len;

    if (len > HP_PEER_MSG_MAX_SIZE)
    {
        fprintf(stderr, "Peer message exceeds max length %d.", HP_PEER_MSG_MAX_SIZE);
        return -1;
    }

    return writev(__hpc.cctx->peers.fd, bufs, buf_count);
}

/**
 * Reads a peer message (NPL) while waiting for 'timeout' milliseconds.
 * @param msg_buf The buffer to place the incoming message. Must be of at least 'HP_PEER_MSG_MAX_SIZE' length.
 * @param pubkey_buf The buffer to place the sender pubkey (hex). Must be of at least 'HP_KEY_SIZE' length.
 * @param timeout Maximum milliseoncds to wait until a message arrives. If 0, returns immediately.
 *                If -1, waits forever until message arrives.
 * @return Message length on success. 0 if no message arrived within timeout. -1 on error.
 */
int hp_read_peer_msg(void *msg_buf, char *pubkey_buf, const int timeout)
{
    struct pollfd pfd = {__hpc.cctx->peers.fd, POLLIN, 0};

    // Peer messages consist of alternating SEQ packets of pubkey and data.
    // So we need to wait for both pubkey and data packets to form a complete peer message.

    // Wait for the pubkey.
    if (poll(&pfd, 1, timeout) == -1)
    {
        perror("Peer channel pubkey poll error");
        return -1;
    }
    else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
    {
        fprintf(stderr, "Peer channel pubkey poll returned error: %d\n", pfd.revents);
        return -1;
    }
    else if (pfd.revents & POLLIN)
    {
        // Read pubkey.
        if (read(pfd.fd, pubkey_buf, HP_KEY_SIZE) == -1)
        {
            perror("Error reading pubkey from peer channel");
            return -1;
        }

        // Wait for data. (data should be available immediately because we have received the pubkey)
        pfd.revents = 0;
        if (poll(&pfd, 1, 100) == -1)
        {
            perror("Peer channel data poll error");
            return -1;
        }
        else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            fprintf(stderr, "Peer channel data poll returned error: %d\n", pfd.revents);
            return -1;
        }
        else if (pfd.revents & POLLIN)
        {
            // Read data.
            const int readres = read(pfd.fd, msg_buf, HP_PEER_MSG_MAX_SIZE);
            if (readres == -1)
            {
                perror("Error reading pubkey from peer channel");
                return -1;
            }
            return readres;
        }
    }

    return 0;
}

/**
 * Updates the UNL of this node with specified 'add' and 'remove' changesets.
 * @param add Array of hex pubkeys of 'HP_KEY_SIZE' to add.
 * @param add_count Number of elements in 'add' array.
 * @param remove Array of hex pubkeys of 'HP_KEY_SIZE' to remove.
 * @param remove_count Number of elements in 'add' remove.
 * @return 0 on success. -1 on error.
 */
int hp_update_unl(const char *add, const size_t add_count, const char *remove, const size_t remove_count)
{
    // We assume 'add' and 'remove' are pointing to a char buffer containing 'count' no. of char[64] buffers.

    // Calculate total json message length and prepare the json buf.
    // Format: {"type":"unl_changeset","add":["pubkey1",...],"remove":["pubkey2",...]}

    const size_t json_size = 45 + (67 * add_count - (add_count ? 1 : 0)) + (67 * remove_count - (remove_count ? 1 : 0));
    char json_buf[json_size];

    strncpy(json_buf, "{\"type\":\"unl_changeset\",\"add\":[", 31);
    size_t pos = 31;
    for (int i = 0; i < add_count; i++)
    {
        if (i > 0)
            json_buf[pos++] = ',';
        json_buf[pos++] = '"';
        strncpy(json_buf + pos, add + (i * 64), 64);
        pos += 64;
        json_buf[pos++] = '"';
    }

    strncpy(json_buf + pos, "],\"remove\":[", 12);
    pos += 12;
    for (int i = 0; i < remove_count; i++)
    {
        if (i > 0)
            json_buf[pos++] = ',';
        json_buf[pos++] = '"';
        strncpy(json_buf + pos, remove + (i * 64), 64);
        pos += 64;
        json_buf[pos++] = '"';
    }

    strncpy(json_buf + pos, "]}", 2);

    return __hp_write_control_msg(json_buf, json_size);
}

void __hp_parse_args_json(const struct json_object_s *object)
{
    const struct json_object_element_s *elem = object->start;
    struct hp_contract_context *cctx = __hpc.cctx;

    do
    {
        const struct json_string_s *k = elem->name;

        if (strcmp(k->string, "pubkey") == 0)
        {
            __HP_ASSIGN_STRING(cctx->pubkey, elem);
        }
        else if (strcmp(k->string, "ts") == 0)
        {
            __HP_ASSIGN_UINT64(cctx->timestamp, elem);
        }
        else if (strcmp(k->string, "readonly") == 0)
        {
            __HP_ASSIGN_BOOL(cctx->readonly, elem);
        }
        else if (strcmp(k->string, "lcl") == 0)
        {
            __HP_ASSIGN_STRING(cctx->lcl, elem);
        }
        else if (strcmp(k->string, "userinfd") == 0)
        {
            __HP_ASSIGN_INT(cctx->users.in_fd, elem);
        }
        else if (strcmp(k->string, "users") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                const struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                cctx->users.count = user_count;
                cctx->users.list = user_count ? (struct hp_user *)malloc(sizeof(struct hp_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (int i = 0; i < user_count; i++)
                    {
                        struct hp_user *user = &cctx->users.list[i];
                        memcpy(user->pubkey, user_elem->name->string, HP_KEY_SIZE);

                        if (user_elem->value->type == json_type_array)
                        {
                            const struct json_array_s *arr = (struct json_array_s *)user_elem->value->payload;
                            struct json_array_element_s *arr_elem = arr->start;

                            // First element is the output fd.
                            __HP_ASSIGN_INT(user->outfd, arr_elem);
                            arr_elem = arr_elem->next;

                            // Subsequent elements are tupels of [offset, size] of input messages for this user.
                            user->inputs.count = arr->length - 1;
                            user->inputs.list = user->inputs.count ? (struct hp_user_input *)malloc(user->inputs.count * sizeof(struct hp_user_input)) : NULL;
                            for (int i = 0; i < user->inputs.count; i++)
                            {
                                if (arr_elem->value->type == json_type_array)
                                {
                                    const struct json_array_s *input_info = (struct json_array_s *)arr_elem->value->payload;
                                    if (input_info->length == 2)
                                    {
                                        __HP_ASSIGN_UINT64(user->inputs.list[i].offset, input_info->start);
                                        __HP_ASSIGN_UINT64(user->inputs.list[i].size, input_info->start->next);
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
            __HP_ASSIGN_INT(cctx->peers.fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                const struct json_array_s *peer_array = (struct json_array_s *)elem->value->payload;
                const size_t peer_count = peer_array->length;

                cctx->peers.count = peer_count;
                cctx->peers.list = peer_count ? (struct hp_peer *)malloc(sizeof(struct hp_peer) * peer_count) : NULL;

                if (peer_count > 0)
                {
                    struct json_array_element_s *peer_elem = peer_array->start;
                    for (int i = 0; i < peer_count; i++)
                    {
                        __HP_ASSIGN_STRING(cctx->peers.list[i].pubkey, peer_elem);
                        peer_elem = peer_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "controlfd") == 0)
        {
            __HP_ASSIGN_INT(__hpc.control_fd, elem);
        }

        elem = elem->next;
    } while (elem);
}

int __hp_write_control_msg(const void *buf, const uint32_t len)
{
    if (len > __HP_SEQPKT_MAX_SIZE)
    {
        fprintf(stderr, "Control message exceeds max length %d.", __HP_SEQPKT_MAX_SIZE);
        return -1;
    }

    return write(__hpc.control_fd, buf, len);
}

void __hp_free(void *ptr)
{
    free(ptr);
    ptr = NULL;
}

#endif