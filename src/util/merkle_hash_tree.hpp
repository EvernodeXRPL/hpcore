#ifndef _HP_UTIL_MERKLE_HASH_TREE_
#define _HP_UTIL_MERKLE_HASH_TREE_

#include "../pchheader.hpp"

namespace util
{
    struct merkle_hash_tree_node
    {
        std::string hash;
        std::vector<merkle_hash_tree_node> children;
    };

    class merkle_hash_tree
    {
    public:
        merkle_hash_tree(const uint16_t block_size);
        void add(std::string_view hash);
        const std::string root();
        const merkle_hash_tree_node collapse(std::string_view retain_hash);
        bool empty();
        void clear();
    };
} // namespace util

#endif