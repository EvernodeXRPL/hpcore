#ifndef _HP_UNL_
#define _HP_UNL_

#include "pchheader.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    size_t count();
    std::unordered_set<std::string> get();
    std::string get_json();
    bool exists(const std::string &bin_pubkey);
    void add(const std::vector<std::string> &additions);
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals);
    void update_json_list();

} // namespace unl

#endif
