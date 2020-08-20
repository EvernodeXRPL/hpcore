#ifndef _HP_COREBILL_
#define _HP_COREBILL_

#include "../pchheader.hpp"

namespace corebill
{

/**
 * Keeps the violation counter and the timestamp of the monitoring window.
 */
struct violation_stat
{
    uint32_t counter = 0;
    uint64_t timestamp = 0;
};

void report_violation(const std::string host);
void add_to_whitelist(const std::string host);
bool is_banned(const std::string &host);

} // namespace corebill

#endif