#include "util/util.hpp"
#include "hplog.hpp"
#include "conf.hpp"
#include "unl.hpp"
#include "crypto.hpp"
#include "p2p/p2p.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    std::set<std::string> list; // List of binary pubkeys of UNL.
    std::string json_list;      // Stringified json array of UNL. (To be fed into the contract args)
    std::shared_mutex unl_mutex;

    unl_changeset changeset;
    std::mutex changeset_mutex;

    /**
     * Called by conf during startup to populate configured unl list.
     */
    void init(const std::set<std::string> &init_list)
    {
        if (init_list.empty())
            return;

        std::unique_lock lock(unl_mutex);
        list = init_list;
        update_json_list();
    }

    size_t count()
    {
        std::shared_lock lock(unl_mutex);
        return list.size();
    }

    std::set<std::string> get()
    {
        std::shared_lock lock(unl_mutex);
        return list;
    }

    std::string get_json()
    {
        std::shared_lock lock(unl_mutex);
        return json_list;
    }

    /**
     * Check whether the given pubkey is in the unl list.
     * @param bin_pubkey Pubkey to check for existence.
     * @return Return true if the given pubkey is in the unl list.
    */
    bool exists(const std::string &bin_pubkey)
    {
        std::shared_lock lock(unl_mutex);
        return list.find(bin_pubkey) != list.end();
    }

    /**
     * Called by contract to update unl at runtime.
     */
    void update(const std::set<std::string> &additions, const std::set<std::string> &removals)
    {
        if (additions.empty() && removals.empty())
            return;

        std::unique_lock lock(unl_mutex);
        const size_t initial_count = list.size();

        for (const std::string &pubkey : additions)
            list.emplace(pubkey);

        for (const std::string &pubkey : removals)
            list.erase(pubkey);

        update_json_list();
        conf::persist_unl_update(list);

        const size_t updated_count = list.size();

        // Unlock unique lock. A shared lock is applied to the list inside the update unl connection function
        // because it use unl::exists function call.
        lock.unlock();

        // Update the is_unl flag of peer sessions.
        if (initial_count != updated_count)
            p2p::update_unl_connections();

        LOG_INFO << "UNL updated. Count:" << updated_count;
    }

    void update_json_list()
    {
        std::ostringstream os;
        os << "[";
        for (auto pk = list.begin(); pk != list.end(); pk++)
        {
            if (pk != list.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary pubkey into hex.
            std::string pubkeyhex;
            util::bin2hex(
                pubkeyhex,
                reinterpret_cast<const unsigned char *>(pk->data()) + 1,
                pk->length() - 1);

            os << "\"" << pubkeyhex << "\"";
        }
        os << "]";
        json_list = os.str();
    }

} // namespace unl
