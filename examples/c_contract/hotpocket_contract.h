#ifndef HOTPOCKET_CONTRACT_LIB
#define HOTPOCKET_CONTRACT_LIB

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include "json.h"

#define __HOTPOCKET_KEY_SIZE 64
#define __HOTPOCKET_HASH_SIZE 64

#define __HOTPOCKET_ASSIGN_STRING(dest, elem)                                       \
    if (elem->value->type == json_type_string)                                      \
    {                                                                               \
        struct json_string_s *value = (struct json_string_s *)elem->value->payload; \
        memcpy(dest, value->string, sizeof(dest));                                  \
    }

#define __HOTPOCKET_ASSIGN_UINT64(dest, elem)                                       \
    if (elem->value->type == json_type_number)                                      \
    {                                                                               \
        struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = strtoull(value->number, NULL, 0);                                    \
    }

#define __HOTPOCKET_ASSIGN_INT(dest, elem)                                          \
    if (elem->value->type == json_type_number)                                      \
    {                                                                               \
        struct json_number_s *value = (struct json_number_s *)elem->value->payload; \
        dest = atoi(value->number);                                                 \
    }

#define __HOTPOCKET_ASSIGN_BOOL(dest, elem)        \
    if (elem->value->type == json_type_true)       \
        dest = true;                               \
    else if (elem->value->type == json_type_false) \
        dest = false;

struct hotpocket_user
{
    char pubkey[__HOTPOCKET_KEY_SIZE + 1];
    int fd;
};

struct hotpocket_peer
{
    char pubkey[__HOTPOCKET_KEY_SIZE + 1];
};

struct hotpocket_users_collection
{
    struct hotpocket_user *list;
    size_t count;
};

struct hotpocket_peers_collection
{
    struct hotpocket_peer *list;
    size_t count;
    int fd;
};

struct hotpocket_context
{
    bool readonly;

    uint64_t timestamp;
    char pubkey[__HOTPOCKET_KEY_SIZE + 1];

    char lcl_hash[__HOTPOCKET_HASH_SIZE + 1];
    uint64_t lcl_seq_no;

    struct hotpocket_users_collection users;
    struct hotpocket_peers_collection peers;
    int control_fd;
};

typedef void (*hotpocket_contract_func)(const struct hotpocket_context *ctx);
typedef void (*hotpocket_user_message_func)(const struct hotpocket_user *user, const void *buf, const size_t len);
typedef void (*hotpocket_peer_message_func)(const char *peerPubKey, const void *buf, const size_t len);

int hotpocket_init();
int hotpocket_run(const struct hotpocket_context *ctx, hotpocket_user_message_func on_user_message, hotpocket_peer_message_func on_peer_message);
void __hotpocket_parse_args_json(struct hotpocket_context *ctx, const struct json_object_s *object);

int hotpocket_init(hotpocket_contract_func contract_func)
{
    // char buf[4096];
    // const int len = read(STDIN_FILENO, buf, sizeof(buf));
    // if (len == -1)
    //     return -1;

    const char *buf = "{\"version\":\"0.1\",\"pubkey\":\"265fd04af73d9be80d545c6de845f8d9dc016e25ebec4ba53a9349f81b7f2eb4\",\"ts\":1605589995570,\"readonly\":false,\"lcl\":\"2213-70332e9068cbe81a458c0ce6dbeed68377d65af96b3d44adc87407397e1caf86\",\"nplfd\":6,\"hpfd\":8,\"usrfd\":{\"265fd04af73d9be80d545c6de845f8d9dc016e25ebec4ba53a9349f81b7f2eb4\":23},\"unl\":[\"265fd04af73d9be80d545c6de845f8d9dc016e25ebec4ba53a9349f81b7f2eb4\"]}";
    const int len = strlen(buf);

    struct json_value_s *root = json_parse(buf, len);
    if (root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        if (object->length > 0)
        {
            // Create and populate hotpocket context.
            struct hotpocket_context ctx;
            memset(&ctx, 0, sizeof(struct hotpocket_context));
            __hotpocket_parse_args_json(&ctx, object);
            free(root);

            // Execute user defined contract function.
            if (contract_func)
                contract_func(&ctx);
            return 0;
        }
    }

    free(root);
    return -1;
}

int hotpocket_run(const struct hotpocket_context *ctx, hotpocket_user_message_func on_user_message, hotpocket_peer_message_func on_peer_message)
{
    // We poll user fds, control fd and npl fd (npl fd not available in read only mode)
    const size_t total_users = ctx->users.count;
    const int fd_count = total_users + (ctx->readonly ? 1 : 2);
    size_t remaining_users = total_users;

    // Create fd set to be polled.
    struct pollfd pollfds[fd_count];
    for (int i = 0; i < pollfds; i++)
    {
        int fd = 0;
        if (i < total_users)
            fd = ctx->users.list[i].fd;
        else if (i == total_users)
            fd = ctx->control_fd;
        else
            fd = ctx->peers.fd; // This will not occur in readonly mode.

        pollfds[0].fd = fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
    }

    while (remaining_users > 0)
    {
        // Cleanup poll fd set because we are reusing it.
        for (int i = 0; i < pollfds; i++)
            pollfds[0].revents = 0;

        if (poll(pollfds, fd_count, 20) == -1)
            goto error;

        for (int i = 0; i < pollfds; i++)
        {
            if (pollfds[i].revents == 0)
                continue;
                
            if (pollfds[i].revents & POLLIN)
            {
                
            }
        }
    }

    return 0;

error:
    return -1;
}

void __hotpocket_parse_args_json(struct hotpocket_context *ctx, const struct json_object_s *object)
{
    struct json_object_element_s *elem = object->start;
    do
    {
        struct json_string_s *k = elem->name;

        if (strcmp(k->string, "pubkey") == 0)
        {
            __HOTPOCKET_ASSIGN_STRING(ctx->pubkey, elem);
        }
        else if (strcmp(k->string, "ts") == 0)
        {
            __HOTPOCKET_ASSIGN_UINT64(ctx->timestamp, elem);
        }
        else if (strcmp(k->string, "readonly") == 0)
        {
            __HOTPOCKET_ASSIGN_BOOL(ctx->readonly, elem);
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
                memcpy(ctx->lcl_hash, hash_str, __HOTPOCKET_HASH_SIZE);
            }
        }
        else if (strcmp(k->string, "usrfd") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                ctx->users.count = user_count;
                ctx->users.list = user_count ? (struct hotpocket_user *)malloc(sizeof(struct hotpocket_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (int i = 0; i < user_count; i++)
                    {
                        memcpy(ctx->users.list[i].pubkey, user_elem->name->string, __HOTPOCKET_KEY_SIZE);
                        __HOTPOCKET_ASSIGN_INT(ctx->users.list[i].fd, user_elem);

                        user_elem = user_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "nplfd") == 0)
        {
            __HOTPOCKET_ASSIGN_INT(ctx->peers.fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                struct json_array_s *peer_array = (struct json_array_s *)elem->value->payload;
                const size_t peer_count = peer_array->length;

                ctx->peers.count = peer_count;
                ctx->peers.list = peer_count ? (struct hotpocket_peer *)malloc(sizeof(struct hotpocket_peer) * peer_count) : NULL;

                if (peer_count > 0)
                {
                    struct json_array_element_s *peer_elem = peer_array->start;
                    for (int i = 0; i < peer_count; i++)
                    {
                        __HOTPOCKET_ASSIGN_STRING(ctx->peers.list[i].pubkey, peer_elem);
                        peer_elem = peer_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "hpfd") == 0)
        {
            __HOTPOCKET_ASSIGN_INT(ctx->control_fd, elem);
        }

        elem = elem->next;
    } while (elem);
}

#endif