#ifndef HPSH_H
#define HPSH_H

#include "../conf.hpp"
#include "../util/util.hpp"

namespace hpsh
{
    int deinit();
    int init();
    std::string serve(const char* command);
}

#endif