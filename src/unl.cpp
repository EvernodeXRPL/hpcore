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
    std::map<std::string, uint16_t> list; // List of binary pubkeys of UNL and their latest reported roundtime.
    std::string json_list;                // Stringified json array of UNL. (To be fed into the contract args)
    std::shared_mutex unl_mutex;

    /**
     * Performs startup activitites related to unl list.
     * @return 0 for successful initialization. -1 for failure.
     */
    int init()
    {
        if (conf::cfg.contract.unl.empty())
            return -1;

        std::unique_lock lock(unl_mutex);
        update_unl_list(conf::cfg.contract.unl);

        return 0;
    }

    size_t count()
    {
        std::shared_lock lock(unl_mutex);
        return list.size();
    }

    const std::set<std::string> get()
    {
        std::shared_lock lock(unl_mutex);
        std::set<std::string> ret;
        for (auto [pubkey, roundtime] : list)
            ret.emplace(std::move(pubkey));
        return ret;
    }

    const std::string get_json()
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
     * Replace the unl list from the latest unl list from patch file.
    */
    void update_unl_changes_from_patch()
    {
        bool is_unl_list_changed = false;
        {
            std::unique_lock lock(unl_mutex);
            is_unl_list_changed = update_unl_list(conf::cfg.contract.unl);
        }

        // Update the is_unl flag of peer sessions.
        // Broadcast changed unl list to all the connected users.
        if (is_unl_list_changed)
        {
            p2p::update_unl_connections();
            usr::announce_unl_list(conf::cfg.contract.unl);
        }
    }

    uint16_t get_majority_roundtime()
    {
        std::unique_lock lock(unl_mutex);

        // Vote and find majority roundtime within the unl.
        // Fill any 0 roundtimes with information from peer connections.
        std::map<uint16_t, uint32_t> roundtime_votes;

        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

            for (auto itr = list.begin(); itr != list.end();)
            {
                // If roundtime is 0, attempt to get from peer connection (if available).
                if (itr->second == 0)
                {
                    const auto peer_itr = p2p::ctx.peer_connections.find(itr->first);
                    if (peer_itr != p2p::ctx.peer_connections.end())
                        itr->second = peer_itr->second->reported_roundtime;
                }

                const uint16_t roundtime = itr->second;
                if (roundtime > 0)
                    roundtime_votes[roundtime]++;
            }
        }

        // Find the majority vote.
        uint32_t highest_votes = 0;
        uint16_t majority_roundtime = 0;
        for (const auto [roundtime, num_votes] : roundtime_votes)
        {
            if (num_votes > highest_votes)
            {
                highest_votes = num_votes;
                majority_roundtime = roundtime;
            }
        }

        return majority_roundtime;
    }

    /**
     * Updates the unl list using the provided new list.
     * @return Whether or not any unl list changes were made.
     */
    bool update_unl_list(const std::set<std::string> &new_list)
    {
        bool changes_made = false;

        // Erase any pubkeys from current unl list that does not exist in new config.
        for (auto itr = list.begin(); itr != list.end();)
        {
            if (conf::cfg.contract.unl.count(itr->first) == 0)
            {
                itr = list.erase(itr);
                changes_made = true;
            }
            else
            {
                itr++;
            }
        }

        // Add any pubkeys that are not in current unl list.
        for (const std::string pubkey : conf::cfg.contract.unl)
        {
            if (list.count(pubkey) == 0)
            {
                list.emplace(pubkey, 0);
                changes_made = true;
            }
        }

        if (!changes_made)
            return false;

        // Update the prepared json list which will be fed into contract args.
        json_list = prepare_json_list(new_list);

        // Update the own node's unl status.
        conf::cfg.node.is_unl = (list.count(conf::cfg.node.public_key) == 1);

        return true; // Changes made.
    }

    const std::string prepare_json_list(const std::set<std::string> &new_list)
    {
        std::ostringstream os;
        os << "[";
        for (auto pk = new_list.begin(); pk != new_list.end(); pk++)
        {
            if (pk != new_list.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary pubkey into hex.
            os << "\"" << util::to_hex(*pk) << "\"";
        }
        os << "]";
        return os.str();
    }

} // namespace unl
