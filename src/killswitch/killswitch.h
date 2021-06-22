#ifndef KILLSWITCH_H
#define KILLSWITCH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool kill_switch(const uint64_t epoch_ms);

#ifdef __cplusplus
};
#endif

#endif

