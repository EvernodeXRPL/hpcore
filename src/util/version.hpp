#ifndef _HP_UTIL_VERSION_
#define _HP_UTIL_VERSION_

#include "../pchheader.hpp"

namespace version
{
    // HotPocket version. Written to new configs and p2p/user messages.
    constexpr const char *HP_VERSION = "0.6.2";

    // Minimum compatible config version (this will be used to validate configs).
    constexpr const char *MIN_CONFIG_VERSION = "0.6.2";

    // Ledger file storage version. All nodes in a cluster MUST use the same ledger version.
    constexpr const char *LEDGER_VERSION = "0.5.0";

    // Version header size in bytes when serialized in binary format. (applies to hp version as well as ledger version)
    // 2 bytes each for 3 version components. 2 bytes reserved.
    constexpr const size_t VERSION_BYTES_LEN = 8;

    // Hpfs version header length. This is currently same length as hpcore version header.
    // This value needs to be updated when hpfs version header length changes.
    constexpr const size_t HPFS_VERSION_BYTES_LEN = 8;

    // Binary representations of the versions. (populated during version init)
    extern uint8_t HP_VERSION_BYTES[VERSION_BYTES_LEN];
    extern uint8_t LEDGER_VERSION_BYTES[VERSION_BYTES_LEN];

    int init();

    int version_compare(const std::string &x, const std::string &y);

    int set_version_bytes(uint8_t *bytes, std::string_view version);

}

#endif