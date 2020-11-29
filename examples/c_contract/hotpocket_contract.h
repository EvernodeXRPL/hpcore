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
    char pubkey[__HP_KEY_SIZE + 1];
    char lcl[__HP_HASH_SIZE + 22]; // uint64(20 chars) + "-" + hash + nullchar
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

void __hp_parse_args_json(const struct json_object_s *object);
int __hp_write_control(const uint8_t *buf, const uint32_t len);
void __hp_free(void *ptr);

static struct __hp_contract __hpc = {};

int hp_init_contract()
{
    if (__hpc.cctx)
        return -1; // Already initialized.

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
            __hp_free(cctx->users.list[i].inputs);

        __hp_free(cctx->users.list);
    }
    // Cleanup peer list allocation.
    __hp_free(cctx->peers.list);
    // Cleanup contract context.
    __hp_free(cctx);

    // Send termination control message.
    __hp_write_control("{\"type\":\"contract_end\"}", 23);
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
                            user->inputs = user->inputs_count ? (struct hp_user_input *)malloc(user->inputs_count * sizeof(struct hp_user_input)) : NULL;
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

int __hp_write_control(const uint8_t *buf, const uint32_t len)
{
    if (len > __HP_SEQPKT_BUF_SIZE)
    {
        fprintf(stderr, "Control message exceeds max length %d.", __HP_SEQPKT_BUF_SIZE);
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