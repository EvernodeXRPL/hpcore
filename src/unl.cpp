#include "unl.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    std::unordered_set<std::string> list; // List of binary pubkeys of UNL.
    std::shared_mutex unl_mutex;

    size_t count()
    {
        std::shared_lock lock(unl_mutex);
        return list.size();
    }

    std::unordered_set<std::string> get()
    {
        std::shared_lock lock(unl_mutex);
        return list;
    }

    bool exists(const std::string &bin_pubkey)
    {
        std::shared_lock lock(unl_mutex);
        return list.find(bin_pubkey) != list.end();
    }

    void add(const std::vector<std::string> &additions)
    {
        if (additions.empty())
            return;

        std::unique_lock lock(unl_mutex);

        for (const std::string &pubkey : additions)
            list.emplace(pubkey);
    }

    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals)
    {
        if (additions.empty() && removals.empty())
            return;

        std::unique_lock lock(unl_mutex);

        for (const std::string &pubkey : additions)
            list.emplace(pubkey);

        for (const std::string &pubkey : removals)
            list.erase(pubkey);
    }

} // namespace unl
