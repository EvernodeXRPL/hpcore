#ifndef _HP_UNL_
#define _HP_UNL_

#include "pchheader.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    size_t count();
    std::set<std::string> get();
    std::string get_json();
    bool exists(std::string pubkey, const bool is_in_hex = false);
    void init(const std::set<std::string> &init_list);
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals);
    void update_json_list();

} // namespace unl

#endif
