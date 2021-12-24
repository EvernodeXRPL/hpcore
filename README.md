# Hot Pocket Consensus Engine

## What's here?
*In development*

A C++ version of hotpocket designed for production envrionments, original prototype here: https://github.com/codetsunami/hotpocket

## Libraries
* Crypto - Libsodium https://github.com/jedisct1/libsodium
* jsoncons (for JSON and BSON) - https://github.com/danielaparker/jsoncons
* P2P Protocol - https://google.github.io/flatbuffers
* Fuse filesystem - https://github.com/libfuse/libfuse
* Reader Writer Queue - https://github.com/cameron314/readerwriterqueue
* Concurrent Queue - https://github.com/cameron314/concurrentqueue
* Boost Stacktrace - https://www.boost.org

## Setting up Hot Pocket development environment
Run the setup script located at the repo root (tested on Ubuntu 20.04).
```
./dev-setup.sh
```

## Build Hot Pocket
1. Run `cmake .` (You only have to do this once)
1. Run `make` (Hot Pocket binary will be created as `./build/hpcore`)
1. Refer to the Wiki for instructions on running Hot Pocket.

## FlatBuffers message definitions
If you update flatbuffers message definitions, you need to run the flatbuffers code generator to update the stubs.

Example: When you make a change to `p2pmsg.fbs` defnition file, you need to run this:

`flatc -o src/msg/fbuf/ --gen-mutable --cpp src/msg/fbuf/p2pmsg.fbs`

## Code structure
Code is divided into subsystems via namespaces.

**conf::** Handles configuration. Loads and holds the central configuration object. Used by most of the subsystems.

**crypto::** Handles cryptographic activities. Wraps libsodium and offers convenience functions.

**sc::** Handles smart contract process execution and managing user/SC I/O and npl I/O. Makes use of **usr**, **p2p** and **hpfs**.

**usr::** Handles user connections. Makes use of **crypto** and **comm**.

**p2p::** Handles peer-to-peer connections and message exchange between nodes. Makes use of **crypto** and **comm**.

**consensus::** Handles consensus and proposal rounds. Makes use of **usr**, **p2p** and **sc**

**ledger::** Maintains the ledger and handles ledger syncing activites.

**comm::** Handles generic web sockets communication functionality. Mainly acts as a wrapper for [hpws](https://github.com/RichardAH/hpws).

**util::** Contains shared data structures/helper functions used by multiple subsystems.

**hpfs::** [hpfs](https://github.com/HotPocketDev/hpfs) state management client helpers.