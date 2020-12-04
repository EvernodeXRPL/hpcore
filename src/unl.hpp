#ifndef _HP_UNL_
#define _HP_UNL_

#include "pchheader.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    struct unl_changeset
    {
        std::set<std::string> additions; // Pubkeys of the peers that need to be added to the unl.
        std::set<std::string> removals;  // Pubkeys of the peers that need to be removed from the unl.
    };

    extern unl_changeset changeset;
    extern std::mutex changeset_mutex;

    size_t count();
    std::set<std::string> get();
    std::string get_json();
    bool exists(const std::string &bin_pubkey);
    void init(const std::set<std::string> &init_list);
    void update(const std::set<std::string> &additions, const std::set<std::string> &removals);
    void update_json_list();

} // namespace unl

#endif
