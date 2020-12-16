#include "../pchheader.hpp"
#include "../crypto.hpp"
#include "merkle_hash_tree.hpp"

namespace util
{
    merkle_hash_tree::merkle_hash_tree(const size_t block_size) : block_size(block_size)
    {
    }

    void merkle_hash_tree::add(std::string_view hash)
    {
        root_node.children.emplace_back(hash);

        if (root_node.hash.empty())
        {
            root_node.hash = hash;
        }
        else
        {
            root_node.hash = crypto::get_hash(root_node.hash, hash);
        }
    }

    const std::string merkle_hash_tree::root()
    {
        return root_node.hash;
    }

    const merkle_hash_tree_node merkle_hash_tree::collapse(std::string_view retain_hash)
    {
        return root_node;
    }

    bool merkle_hash_tree::empty()
    {
        return root_node.hash.empty();
    }

    void merkle_hash_tree::clear()
    {
        root_node.hash.clear();
        root_node.children.clear();
    }

} // namespace util