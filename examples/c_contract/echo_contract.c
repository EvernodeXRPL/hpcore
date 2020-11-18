#include "hotpocket_contract.h"

// gcc echo_contract.c -o echo_contract && ./echo_contract

int main(int argc, char **argv)
{
    if (hotpocket_init() == -1)
        return 1;

    return 0;
}