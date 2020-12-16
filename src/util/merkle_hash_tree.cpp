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
        root.children.emplace_back(hash);

        if (root.hash.empty())
        {
            root.hash = hash;
        }
        else
        {
            root.hash = crypto::get_hash(root.hash, hash);
        }
    }

    const std::string merkle_hash_tree::root_hash()
    {
        return root.hash;
    }

    const merkle_hash_tree_node merkle_hash_tree::collapse(std::string_view retain_hash)
    {
        return root;
    }

    bool merkle_hash_tree::empty()
    {
        return root.hash.empty();
    }

    void merkle_hash_tree::clear()
    {
        root.hash.clear();
        root.children.clear();
    }

} // namespace util