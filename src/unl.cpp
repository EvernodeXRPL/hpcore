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
     * @param pubkey Pubkey to check for existence.
     * @param is_in_hex Whether the given pubkey is in hex format.
     * @return Return true if the given pubkey is in the unl list.
    */
    bool exists(std::string pubkey, const bool is_in_hex)
    {
        if (is_in_hex)
        {
            // If the given pubkey is in hex format, convert the public key to binary.
            std::string bin_pubkey;
            bin_pubkey.resize(crypto::PFXD_PUBKEY_BYTES);
            if (util::hex2bin(
                    reinterpret_cast<unsigned char *>(bin_pubkey.data()),
                    bin_pubkey.length(),
                    pubkey) != 0)
            {
                LOG_ERROR << "Error decoding hex pubkey.\n";
                return false;
            }
            pubkey.swap(bin_pubkey);
        }
        std::shared_lock lock(unl_mutex);
        return list.find(pubkey) != list.end();
    }

    /**
     * Called by contract to update unl at runtime.
     */
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals)
    {
        if (additions.empty() && removals.empty())
            return;

        std::unique_lock lock(unl_mutex);

        for (const std::string &pubkey : additions)
            list.emplace(pubkey);

        for (const std::string &pubkey : removals)
            list.erase(pubkey);

        update_json_list();
        conf::persist_unl_update(list);

        LOG_INFO << "UNL updated. Count:" << list.size();
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
