#include "../pchheader.hpp"
#include "../crypto.hpp"
#include "util.hpp"
#include "merkle_hash_tree.hpp"

namespace util
{
    merkle_hash_tree::merkle_hash_tree(const size_t block_size) : block_size(block_size)
    {
    }

    void merkle_hash_tree::create_groups(std::list<merkle_hash_node> &nodes)
    {
        if (nodes.size() == 1)
        {
            merkle_hash_node &first = nodes.front();
            root.hash.swap(first.hash);
            root.children.swap(first.children);
        }
        else if (nodes.size() > 1)
        {
            // Create parent hash nodes for blocks of nodes.
            std::list<merkle_hash_node> parents;

            const size_t blocks = (nodes.size() + block_size - 1) / block_size;
            for (int i = 0; i < blocks; i++)
            {
                parents.push_back({});
                merkle_hash_node &parent = parents.back();

                // Move a portion of nodes under the parent.
                auto last_child = nodes.begin();
                std::advance(last_child, MIN(block_size, nodes.size()));
                parent.children.splice(parent.children.end(), nodes, nodes.begin(), last_child);

                // Calculate parent hash.
                if (parent.children.size() > 1)
                {
                    std::vector<std::string_view> hashes;
                    for (const util::merkle_hash_node &child : parent.children)
                        hashes.push_back(child.hash);
                    parent.hash = crypto::get_hash(hashes);
                }
                else
                {
                    // If parent has a single child, the child becomes the parent.
                    parent.hash.swap(parent.children.begin()->hash);
                    parent.children.swap(parent.children.begin()->children);
                }
            }

            create_groups(parents);
        }
    }

    void print(const merkle_hash_node &node)
    {
        std::cout << util::to_hex(node.hash).substr(0, 8);

        if (!node.children.empty())
        {
            std::cout << "(";
            for (const merkle_hash_node &child : node.children)
            {
                print(child);
                std::cout << " ";
            }
            std::cout << ") ";
        }
    }

    void merkle_hash_tree::populate(const std::vector<std::string_view> &hashes)
    {
        // Create leaf tree nodes for all hashes.
        std::list<merkle_hash_node> leafs;
        for (std::string_view hash : hashes)
            leafs.push_back(merkle_hash_node{std::string(hash)});

        create_groups(leafs);

        std::cout << util::to_hex(root.hash).substr(0, 8);
        print(root);
        std::cout << "\n";
    }

    const std::string merkle_hash_tree::root_hash()
    {
        return root.hash;
    }

    const merkle_hash_node merkle_hash_tree::collapse(std::string_view retain_hash)
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