#ifndef _HP_UTIL_MERKLE_HASH_TREE_
#define _HP_UTIL_MERKLE_HASH_TREE_

#include "../pchheader.hpp"

namespace util
{
    struct merkle_hash_node
    {
        std::string hash;
        std::list<merkle_hash_node> children;
    };

    class merkle_hash_tree
    {
    private:
        const size_t block_size;
        merkle_hash_node root;
        void create_groups(std::list<merkle_hash_node> &nodes);
        merkle_hash_node clone(const merkle_hash_node &node);
        bool retain_node(merkle_hash_node &node, std::string_view retain_hash);
        void print(const merkle_hash_node &node);

    public:
        merkle_hash_tree(const size_t block_size);
        void populate(const std::vector<std::string_view> &hashes);
        const std::string root_hash();
        const merkle_hash_node collapse(std::string_view retain_hash);
        bool empty();
        void clear();
    };
} // namespace util

#endif