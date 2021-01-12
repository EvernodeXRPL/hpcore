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
#define HP_NPL_MSG_MAX_SIZE __HP_SEQPKT_MAX_SIZE
#define HP_KEY_SIZE 66 // Hex pubkey size. (64 char key + 2 chars for key type prfix)
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

// Represents a user that is connected to HP cluster.
struct hp_user
{
    char pubkey[HP_KEY_SIZE + 1]; // +1 for null char.S
    int outfd;
    struct hp_user_inputs_collection inputs;
};

// Represents a node that's part of unl.
struct hp_unl_node
{
    char pubkey[HP_KEY_SIZE + 1]; // +1 for null char.S
};

struct hp_users_collection
{
    struct hp_user *list;
    size_t count;
    int in_fd;
};

struct hp_unl_collection
{
    struct hp_unl_node *list;
    size_t count;
    int npl_fd;
};

struct hp_appbill_config
{
    char *mode;
    char *bin_args;
};

struct patch_config
{
    char *version;
    struct hp_unl_collection unl;
    char *bin_path;
    char *bin_args;
    u_int16_t roundtime;
    char *consensus;
    char *npl;
    struct hp_appbill_config appbill;
};

struct hp_contract_context
{
    bool readonly;
    uint64_t timestamp;
    char pubkey[HP_KEY_SIZE + 1]; // +1 for null char.S
    char lcl[HP_HASH_SIZE + 22];  // uint64(20 chars) + "-" + hash + nullchar
    struct hp_users_collection users;
    struct hp_unl_collection unl;
};

struct __hp_contract
{
    struct hp_contract_context *cctx;
    int control_fd;
    void *user_inmap;
    size_t user_inmap_size;
};

const char * PATCH_FILE_PATH = "../patch.cfg";

int hp_init_contract();
int hp_deinit_contract();
const struct hp_contract_context *hp_get_context();
const void *hp_init_user_input_mmap();
void hp_deinit_user_input_mmap();
int hp_write_user_msg(const struct hp_user *user, const void *buf, const uint32_t len);
int hp_writev_user_msg(const struct hp_user *user, const struct iovec *bufs, const int buf_count);
int hp_write_npl_msg(const void *buf, const uint32_t len);
int hp_writev_npl_msg(const struct iovec *bufs, const int buf_count);
int hp_read_npl_msg(void *msg_buf, char *pubkey_buf, const int timeout);
int hp_update_unl(const char *add, const size_t add_count, const char *remove, const size_t remove_count);
int hp_update_config(const struct patch_config *config);

void __hp_parse_args_json(const struct json_object_s *object);
int __hp_write_control_msg(const void *buf, const uint32_t len);
void __hp_populate_patch_from_json_object(struct json_object_s *object, struct patch_config *config);
void __hp_write_to_patch_file(const int fd, const struct patch_config *config);
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

    // Cleanup user and npl fd.
    close(cctx->users.in_fd);
    for (int i = 0; i < cctx->users.count; i++)
        close(cctx->users.list[i].outfd);
    close(cctx->unl.npl_fd);

    // Cleanup user list allocation.
    if (cctx->users.list)
    {
        for (int i = 0; i < cctx->users.count; i++)
            __hp_free(cctx->users.list[i].inputs.list);

        __hp_free(cctx->users.list);
    }
    // Cleanup unl list allocation.
    __hp_free(cctx->unl.list);
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

int hp_write_npl_msg(const void *buf, const uint32_t len)
{
    if (len > HP_NPL_MSG_MAX_SIZE)
    {
        fprintf(stderr, "NPL message exceeds max length %d.", HP_NPL_MSG_MAX_SIZE);
        return -1;
    }

    return write(__hpc.cctx->unl.npl_fd, buf, len);
}

int hp_writev_npl_msg(const struct iovec *bufs, const int buf_count)
{
    uint32_t len = 0;
    for (int i = 0; i < buf_count; i++)
        len += bufs[i].iov_len;

    if (len > HP_NPL_MSG_MAX_SIZE)
    {
        fprintf(stderr, "NPL message exceeds max length %d.", HP_NPL_MSG_MAX_SIZE);
        return -1;
    }

    return writev(__hpc.cctx->unl.npl_fd, bufs, buf_count);
}

/**
 * Reads a NPL message while waiting for 'timeout' milliseconds.
 * @param msg_buf The buffer to place the incoming message. Must be of at least 'HP_NPL_MSG_MAX_SIZE' length.
 * @param pubkey_buf The buffer to place the sender pubkey (hex). Must be of at least 'HP_KEY_SIZE' length.
 * @param timeout Maximum milliseoncds to wait until a message arrives. If 0, returns immediately.
 *                If -1, waits forever until message arrives.
 * @return Message length on success. 0 if no message arrived within timeout. -1 on error.
 */
int hp_read_npl_msg(void *msg_buf, char *pubkey_buf, const int timeout)
{
    struct pollfd pfd = {__hpc.cctx->unl.npl_fd, POLLIN, 0};

    // NPL messages consist of alternating SEQ packets of pubkey and data.
    // So we need to wait for both pubkey and data packets to form a complete NPL message.

    // Wait for the pubkey.
    if (poll(&pfd, 1, timeout) == -1)
    {
        perror("NPL channel pubkey poll error");
        return -1;
    }
    else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
    {
        fprintf(stderr, "NPL channel pubkey poll returned error: %d\n", pfd.revents);
        return -1;
    }
    else if (pfd.revents & POLLIN)
    {
        // Read pubkey.
        if (read(pfd.fd, pubkey_buf, HP_KEY_SIZE) == -1)
        {
            perror("Error reading pubkey from NPL channel");
            return -1;
        }

        // Wait for data. (data should be available immediately because we have received the pubkey)
        pfd.revents = 0;
        if (poll(&pfd, 1, 100) == -1)
        {
            perror("NPL channel data poll error");
            return -1;
        }
        else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            fprintf(stderr, "NPL channel data poll returned error: %d\n", pfd.revents);
            return -1;
        }
        else if (pfd.revents & POLLIN)
        {
            // Read data.
            const int readres = read(pfd.fd, msg_buf, HP_NPL_MSG_MAX_SIZE);
            if (readres == -1)
            {
                perror("Error reading pubkey from NPL channel");
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
    // We assume 'add' and 'remove' are pointing to char buffers containing 'count' no. of char[HP_KEY_SIZE] buffers.

    // Calculate total json message length and prepare the json buf.
    // Format: {"type":"unl_changeset","add":["pubkey1",...],"remove":["pubkey2",...]}

    // {"type":"unl_changeset","add":[],"remove":[]} => length 45
    // "pubkey", (HP_KEY_SIZE+quotes+comma) => length 69
    const size_t json_size = 45 + (69 * add_count - (add_count ? 1 : 0)) + (69 * remove_count - (remove_count ? 1 : 0));
    char json_buf[json_size];

    strncpy(json_buf, "{\"type\":\"unl_changeset\",\"add\":[", 31);
    size_t pos = 31;
    for (int i = 0; i < add_count; i++)
    {
        if (i > 0)
            json_buf[pos++] = ',';
        json_buf[pos++] = '"';
        strncpy(json_buf + pos, add + (i * HP_KEY_SIZE), HP_KEY_SIZE);
        pos += HP_KEY_SIZE;
        json_buf[pos++] = '"';
    }

    strncpy(json_buf + pos, "],\"remove\":[", 12);
    pos += 12;
    for (int i = 0; i < remove_count; i++)
    {
        if (i > 0)
            json_buf[pos++] = ',';
        json_buf[pos++] = '"';
        strncpy(json_buf + pos, remove + (i * HP_KEY_SIZE), HP_KEY_SIZE);
        pos += HP_KEY_SIZE;
        json_buf[pos++] = '"';
    }

    strncpy(json_buf + pos, "]}", 2);

    return __hp_write_control_msg(json_buf, json_size);
}

int hp_update_config(const struct patch_config *config)
{
    struct hp_contract_context *cctx = __hpc.cctx;
    if (cctx->readonly)
    {
        fprintf(stderr, "Config update not allowed in readonly mode.");
        return -1;
    }
    const int fd = open(PATCH_FILE_PATH, O_RDWR);
    struct patch_config existing_patch = {};
    if (fd == -1)
    {
        fprintf(stderr, "Error opening patch.cfg file.\n");
        return -1;
    }
    char buf[4096];
    const size_t len = read(fd, buf, sizeof(buf));
    if (len == -1)
    {
        fprintf(stderr, "Error when reading stdin.\n");
        return -1;
    }

    struct json_value_s *root = json_parse(buf, len);
    if (root && root->type == json_type_object)
    {
        struct json_object_s *object = (struct json_object_s *)root->payload;
        __hp_populate_patch_from_json_object(object, &existing_patch);
        if (config->version)
        {
            if (strlen(config->version) != 0)
            {
                existing_patch.version = config->version;
            }
            else
            {
                fprintf(stderr, "Version cannot be empty.\n");
                return -1;
            }
        }

        if (config->unl.count)
        {
            for (size_t i = 0; i < config->unl.count; i++)
            {
                const size_t pubkey_len = strlen(config->unl.list[i].pubkey);
                if (pubkey_len == 0)
                {
                    fprintf(stderr, "Unl pubkey cannot be empty.\n");
                    return -1;
                }

                if (pubkey_len != HP_KEY_SIZE)
                {
                    fprintf(stderr, "Unl pubkey invalid. Invalid length.\n");
                    return -1;
                }

                if (config->unl.list[i].pubkey[0] != 'e' || config->unl.list[i].pubkey[1] != 'd')
                {
                    fprintf(stderr, "Unl pubkey invalid. Invalid format.\n");
                    return -1;
                }
                // Checking the validity of hexadecimal portion. (without 'ed'). 
                for (size_t j = 2; j < HP_KEY_SIZE; j++)
                {
                    const char current_char = config->unl.list[i].pubkey[j];
                    if ((current_char < 'A' || current_char > 'F') && (current_char < 'a' || current_char > 'f') && (current_char < '0' || current_char > '9'))
                    {
                        fprintf(stderr, "Unl pubkey invalid. Invalid character %c.\n", current_char);
                        return -1;
                    }
                }
                
            }
            existing_patch.unl = config->unl;
        }

        if (config->bin_path)
            existing_patch.bin_path = config->bin_path;

        if (config->bin_args)
            existing_patch.bin_args = config->bin_args;

        if (config->roundtime)
            existing_patch.roundtime = config->roundtime;

        if (config->consensus)
        {
            if (strlen(config->consensus) == 0 || (strcmp(config->consensus, "public") != 0 && strcmp(config->consensus, "private") != 0))
            {
                fprintf(stderr, "Invalid consensus flag. Valid values: public|private\n");
                return -1;
            }
            existing_patch.consensus = config->consensus;
        }

        if (config->npl)
        {
            if (strlen(config->npl) == 0 || (strcmp(config->npl, "public") != 0 && strcmp(config->npl, "private")) != 0)
            {
                fprintf(stderr, "Invalid npl flag. Valid values: public|private\n");
                return -1;
            }
            existing_patch.npl = config->npl;
        }

        if (config->appbill.mode)
            existing_patch.appbill.mode = config->appbill.mode;

        if (config->appbill.bin_args)
            existing_patch.appbill.bin_args = config->appbill.bin_args;

        __hp_write_to_patch_file(fd, &existing_patch);
    }
    close(fd);
    __hp_free(root);

    return 0;
}

void __hp_write_to_patch_file(const int fd, const struct patch_config *config)
{
    struct iovec iov_vec[4];
    const size_t version_len = 21 + strlen(config->version);
    char version_buf[version_len];
    sprintf(version_buf, "{\n    \"version\": \"%s\",\n", config->version);
    iov_vec[0].iov_base = version_buf;
    iov_vec[0].iov_len = version_len;

    const size_t unl_buf_size = 15 + (69 * config->unl.count - (config->unl.count ? 1 : 0));
    char unl_buf[unl_buf_size];

    strncpy(unl_buf, "    \"unl\": [", 12);
    size_t pos = 12;
    for (int i = 0; i < config->unl.count; i++)
    {
        if (i > 0)
            unl_buf[pos++] = ',';
        unl_buf[pos++] = '"';
        strncpy(unl_buf + pos, config->unl.list[i].pubkey, HP_KEY_SIZE);
        pos += HP_KEY_SIZE;
        unl_buf[pos++] = '"';
    }

    strncpy(unl_buf + pos, "],\n", 3);
    iov_vec[1].iov_base = unl_buf;
    iov_vec[1].iov_len = unl_buf_size;

    char *rem_json = "    \"bin_path\": \"%s\",\n    \"bin_args\": \"%s\",\n    \"roundtime\": %d,\n    \"consensus\": \"%s\",\n    \"npl\": \"%s\",\n";
    const size_t rem_json_len = 97 + strlen(config->bin_path) + strlen(config->bin_args) + sizeof(uint16_t) + strlen(config->consensus) + strlen(config->npl);
    char rem_buf[rem_json_len];
    sprintf(rem_buf, rem_json, config->bin_path, config->bin_args, config->roundtime, config->consensus, config->npl);
    iov_vec[2].iov_base = rem_buf;
    iov_vec[2].iov_len = rem_json_len;

    char * appbill_json = "    \"appbill\": {\n        \"mode\": \"%s\",\n        \"bin_args\": \"%s\"\n    }\n}";
    const size_t appbill_json_len = 67 + strlen(config->appbill.mode) + strlen(config->appbill.bin_args);
    char appbill_buf[appbill_json_len];
    sprintf(appbill_buf, appbill_json, config->appbill.mode, config->appbill.bin_args);
    iov_vec[3].iov_base = appbill_buf;
    iov_vec[3].iov_len = appbill_json_len;

    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);
    writev(fd, iov_vec, 4);
}

void __hp_populate_patch_from_json_object(struct json_object_s *object, struct patch_config *config)
{
    const struct json_object_element_s *elem = object->start;
    do
    {
        const struct json_string_s *k = elem->name;

        if (strcmp(k->string, "version") == 0)
        {
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
            config->version = (char *)value->string;
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                const struct json_array_s *unl_array = (struct json_array_s *)elem->value->payload;
                const size_t unl_count = unl_array->length;

                config->unl.count = unl_count;
                config->unl.list = unl_count ? (struct hp_unl_node *)malloc(sizeof(struct hp_unl_node) * unl_count) : NULL;

                if (unl_count > 0)
                {
                    struct json_array_element_s *unl_elem = unl_array->start;
                    for (int i = 0; i < unl_count; i++)
                    {
                        __HP_ASSIGN_STRING(config->unl.list[i].pubkey, unl_elem);
                        unl_elem = unl_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "bin_path") == 0)
        {
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
            config->bin_path = (char *)value->string;
        }
        else if (strcmp(k->string, "bin_args") == 0)
        {
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
            config->bin_args = (char *)value->string;
        }
        else if (strcmp(k->string, "roundtime") == 0)
        {
            const struct json_number_s *value = (struct json_number_s *)elem->value->payload;
            config->roundtime = strtol(value->number, NULL, 0);
        }
        else if (strcmp(k->string, "consensus") == 0)
        {
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
            config->consensus = (char *)value->string;
        }
        else if (strcmp(k->string, "npl") == 0)
        {
            const struct json_string_s *value = (struct json_string_s *)elem->value->payload;
            config->npl = (char *)value->string;
        }
        else if (strcmp(k->string, "appbill") == 0)
        {
            struct json_object_s *object = (struct json_object_s *)elem->value->payload;
            struct json_object_element_s *sub_ele = object->start;
            do
            {
                if (strcmp(sub_ele->name->string, "mode") == 0)
                {
                    const struct json_string_s *value = (struct json_string_s *)sub_ele->value->payload;
                    config->appbill.mode = (char *)value->string;
                }
                else if (strcmp(sub_ele->name->string, "bin_args") == 0)
                {
                    const struct json_string_s *value = (struct json_string_s *)sub_ele->value->payload;
                    config->appbill.bin_args = (char *)value->string;
                }
                sub_ele = sub_ele->next;
            } while (sub_ele);
        }

        elem = elem->next;
    } while (elem);
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
        else if (strcmp(k->string, "timestamp") == 0)
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
        else if (strcmp(k->string, "user_in_fd") == 0)
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
        else if (strcmp(k->string, "npl_fd") == 0)
        {
            __HP_ASSIGN_INT(cctx->unl.npl_fd, elem);
        }
        else if (strcmp(k->string, "unl") == 0)
        {
            if (elem->value->type == json_type_array)
            {
                const struct json_array_s *unl_array = (struct json_array_s *)elem->value->payload;
                const size_t unl_count = unl_array->length;

                cctx->unl.count = unl_count;
                cctx->unl.list = unl_count ? (struct hp_unl_node *)malloc(sizeof(struct hp_unl_node) * unl_count) : NULL;

                if (unl_count > 0)
                {
                    struct json_array_element_s *unl_elem = unl_array->start;
                    for (int i = 0; i < unl_count; i++)
                    {
                        __HP_ASSIGN_STRING(cctx->unl.list[i].pubkey, unl_elem);
                        unl_elem = unl_elem->next;
                    }
                }
            }
        }
        else if (strcmp(k->string, "control_fd") == 0)
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