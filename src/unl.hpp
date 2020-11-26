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
    bool exists(std::string bin_pubkey);
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals);

} // namespace unl

#endif
