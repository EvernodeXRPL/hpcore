#ifndef HOTPOCKET_CONTRACT_LIB
#define HOTPOCKET_CONTRACT_LIB

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
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
    char pubkey[__HOTPOCKET_KEY_SIZE];
    int fd;
};

struct hotpocket_peer
{
    char pubkey[__HOTPOCKET_KEY_SIZE];
};

struct hotpocket_context
{
    bool readonly;

    uint64_t timestamp;
    char pubkey[__HOTPOCKET_KEY_SIZE];

    char lcl_hash[__HOTPOCKET_HASH_SIZE];
    uint64_t lcl_seq_no;

    struct hotpocket_user *users;
    size_t users_count;

    struct hotpocket_peer *peers;
    size_t peers_count;
    int peers_fd;
};

int hotpocket_init();
void __hotpocket_parse_args_json(struct hotpocket_context *ctx, const struct json_object_s *object);

int hotpocket_init()
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
            struct hotpocket_context *ctx = (struct hotpocket_context *)malloc(sizeof(struct hotpocket_context));
            memset(ctx, 0, sizeof(struct hotpocket_context));
            __hotpocket_parse_args_json(ctx, object);

            free(root);
            return 0;
        }
    }

    free(root);
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
        else if (strcmp(k->string, "nplfd") == 0)
        {
            __HOTPOCKET_ASSIGN_INT(ctx->peers_fd, elem);
        }
        else if (strcmp(k->string, "usrfd") == 0)
        {
            if (elem->value->type == json_type_object)
            {
                struct json_object_s *user_object = (struct json_object_s *)elem->value->payload;
                const size_t user_count = user_object->length;

                ctx->users_count = user_count;
                ctx->users = user_count ? (struct hotpocket_user *)malloc(sizeof(struct hotpocket_user) * user_count) : NULL;

                if (user_count > 0)
                {
                    struct json_object_element_s *user_elem = user_object->start;
                    for (int i = 0; i < user_count; i++)
                    {
                        memcpy(ctx->users[i].pubkey, user_elem->name->string, __HOTPOCKET_KEY_SIZE);
                        __HOTPOCKET_ASSIGN_INT(ctx->users[i].fd, user_elem);

                        user_elem = user_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                struct json_array_s *peer_array = (struct json_array_s *)elem->value->payload;
                const size_t peer_count = peer_array->length;

                ctx->peers_count = peer_count;
                ctx->peers = peer_count ? (struct hotpocket_peer *)malloc(sizeof(struct hotpocket_peer) * peer_count) : NULL;

                if (peer_count > 0)
                {
                    struct json_array_element_s *peer_elem = peer_array->start;
                    for (int i = 0; i < peer_count; i++)
                    {
                        __HOTPOCKET_ASSIGN_STRING(ctx->peers[i].pubkey, peer_elem);
                        peer_elem = peer_elem->next;
                    }
                }
            }
        }

        elem = elem->next;
    } while (elem);
}

#endif