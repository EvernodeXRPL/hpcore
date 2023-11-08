#include "util/util.hpp"
#include "hplog.hpp"
#include "conf.hpp"
#include "unl.hpp"
#include "crypto.hpp"
#include "status.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    struct node_stat
    {
        uint32_t time_config = 0;   // Roundtime config of this node.
        uint64_t active_on = 0;     // Latest timestamp we received a proposal from this node.
        util::sequence_hash lcl_id; // Current HotPocket lcl (seq no. and ledger hash hex)
    };

    std::map<std::string, node_stat> list; // List of binary pubkeys of UNL nodes and their statistics.
    std::string json_list;                 // Stringified json array of UNL. (To be fed into the contract args)
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
        merge_latest_unl_config();
        status::init_unl(conf::cfg.contract.unl);

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
        for (auto [pubkey, time_config] : list)
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
            is_unl_list_changed = merge_latest_unl_config();
        }

        if (is_unl_list_changed)
        {
            p2p::update_unl_connections();               // Update the is_unl flag of peer sessions.
            status::unl_changed(conf::cfg.contract.unl); // Update the central node status holder.
        }
    }

    /**
     * Updates unl stats using the specified list of proposals.
     */
    void update_unl_stats(const std::list<p2p::proposal> &proposals)
    {
        std::unique_lock lock(unl_mutex);
        bool changes_made = false;

        for (const auto &p : proposals)
        {
            const auto itr = list.find(p.pubkey);
            if (itr != list.end())
            {
                changes_made = true;
                itr->second.lcl_id = p.lcl_id;
                itr->second.active_on = p.recv_timestamp;
                itr->second.time_config = p.time_config;
            }
        }

        // Update the prepared json list which will be fed into contract args.
        if (changes_made)
            json_list = prepare_json_list();
    }

    /**
     * Returns the majority time config reported among the unl.
     */
    uint32_t get_majority_time_config()
    {
        std::unique_lock lock(unl_mutex);

        // Vote and find majority time config within the unl using values extracted from incoming proposals.
        // Fill any 0 time configs with information from peer connections.
        std::map<uint32_t, uint32_t> time_config_votes;

        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

            for (auto itr = list.begin(); itr != list.end(); itr++)
            {
                // If time config is 0, attempt to get from peer connection (if available).
                if (itr->second.time_config == 0)
                {
                    const auto peer_itr = p2p::ctx.peer_connections.find(itr->first);
                    if (peer_itr != p2p::ctx.peer_connections.end())
                        itr->second.time_config = peer_itr->second->reported_time_config;
                }

                const uint32_t time_config = itr->second.time_config;
                if (time_config > 0)
                    time_config_votes[time_config]++;
            }
        }

        // Find the majority vote.
        uint32_t highest_votes = 0;
        uint32_t majority_time_config = 0;
        for (const auto [time_config, num_votes] : time_config_votes)
        {
            if (num_votes > highest_votes)
            {
                highest_votes = num_votes;
                majority_time_config = time_config;
            }
        }

        return majority_time_config;
    }

    /**
     * Updates the unl list using the latest config unl.
     * @return Whether or not any unl list changes were made.
     */
    bool merge_latest_unl_config()
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
                list.emplace(pubkey, node_stat{});
                changes_made = true;
            }
        }

        if (!changes_made)
            return false;

        // Update the prepared json list which will be fed into contract args.
        json_list = prepare_json_list();

        // Update the own node's unl status.
        conf::cfg.node.is_unl = (list.count(conf::cfg.node.public_key) == 1);

        return true; // Changes made.
    }

    const std::string prepare_json_list()
    {
        std::ostringstream os;
        os << "{";
        for (auto node = list.begin(); node != list.end(); node++)
        {
            if (node != list.begin())
                os << ","; // Trailing comma separator for previous element.

            // Convert binary pubkey into hex.
            os << "\"" << util::to_hex(node->first) << "\":{"
               << "\"active_on\":" << node->second.active_on << ","
               << "\"lcl_seq_no\":" << node->second.lcl_id.seq_no << ","
               << "\"lcl_hash\":\"" << util::to_hex(node->second.lcl_id.hash.to_string_view()) << "\""
               << "}";
        }
        os << "}";
        return os.str();
    }

} // namespace unl
