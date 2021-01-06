#ifndef _HP_UNL_
#define _HP_UNL_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{

    size_t count();
    std::set<std::string> get();
    std::string get_json();
    bool exists(const std::string &bin_pubkey);
    int init();
    void update_json_list();
    std::string get_hash();
    std::string calculate_hash(const std::set<std::string> &new_list);
    void update_unl_changes_from_patch();

} // namespace unl

#endif
