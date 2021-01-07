#include "util/util.hpp"
#include "hplog.hpp"
#include "conf.hpp"
#include "unl.hpp"
#include "crypto.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    std::set<std::string> list; // List of binary pubkeys of UNL.
    std::string json_list;      // Stringified json array of UNL. (To be fed into the contract args)
    std::shared_mutex unl_mutex;
    std::string hash;

    /**
     * Performs startup activitites related to unl list.
     * @return 0 for successful initialization. -1 for failure.
     */
    int init()
    {
        if (conf::cfg.contract.unl.empty())
            return -1;

        std::unique_lock lock(unl_mutex);
        list = conf::cfg.contract.unl;
        // Update the own node's unl status.
        conf::cfg.node.is_unl = (list.find(conf::cfg.node.public_key) != list.end());
        update_json_list();
        hash = calculate_hash(list);
        return 0;
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

    void update_json_list()
    {
        std::ostringstream os;
        os << "[";
        for (auto pk = list.begin(); pk != list.end(); pk++)
        {
            if (pk != list.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary pubkey into hex.
            os << "\"" << util::to_hex(*pk) << "\"";
        }
        os << "]";
        json_list = os.str();
    }

    /**
     * Calculate hash of the given set.
     * @param unl_list UNL list.
     * @return Returns the generated hash of the given list.
    */
    std::string calculate_hash(const std::set<std::string> &new_list)
    {
        std::vector<std::string_view> unl_vector(new_list.begin(), new_list.end());
        return crypto::get_hash(unl_vector);
    }


    /**
     * Replace the unl list from the latest unl list from patch file.
    */
    void update_unl_changes_from_patch()
    {
        bool is_unl_list_changed = false;
        {
            std::unique_lock lock(unl_mutex);
            const std::string updated_hash = calculate_hash(conf::cfg.contract.unl);
            if (hash != updated_hash)
            {
                hash = updated_hash;
                list = conf::cfg.contract.unl;
                update_json_list();

                // Update the own node's unl status.
                conf::cfg.node.is_unl = (list.find(conf::cfg.node.public_key) != list.end());
                is_unl_list_changed = true;
            }
        }

        // Update the is_unl flag of peer sessions.
        if (is_unl_list_changed)
            p2p::update_unl_connections();
    }

} // namespace unl
