# Hot Pocket Consensus Engine

## What's here?
*In development*

A C++ version of hotpocket designed for production envrionments, original prototype here: https://github.com/codetsunami/hotpocket

[Hot Pocket Wiki](https://github.com/HotPocketDev/core/wiki/Hot-Pocket-Wiki)

## Libraries
* Crypto - Libsodium https://github.com/jedisct1/libsodium
* Websockets - Boost|Beast https://github.com/boostorg/beast
* RapidJSON - http://rapidjson.org
* P2P Protocol - https://github.com/protocolbuffers/protobuf

## Steps to setup Hot Pocket

#### Install Libsodium
Instructions are based on [this](https://libsodium.gitbook.io/doc/installation).

1. Download and extract Libsodium 1.0.18 from [here](https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz).
2. Navigate to the extracted libsodium directory in a terminal.
3. Run `./configure`
4. Run `make && make check`
5. Run `sudo make install`

#### Install Boost
Following Instructions are based on Boost [getting started](https://www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html#prepare-to-use-a-boost-library-binary)

1. Download and extract boost 1.71 package from [here](https://www.boost.org/users/history/version_1_71_0.html).
2. Navigate to the extracted boost directory in a terminal.
3. Run `./bootstrap.sh`
4. Run `sudo ./b2 install` (This will compile and install boost libraries into your `/usr/local/lib`)

#### Install RapidJSON
1. Download and extract RapidJSON 1.1 source from [here](https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz).
2. Navigate to the extracted directory.
3. Run `sudo cp -r include/rapidjson /usr/local/include/`

#### Install Protocol buffers
Instructions are based on [this](https://github.com/protocolbuffers/protobuf/tree/master/src).

1. Download and extract Protobuf 3.10.0 from [here](https://github.com/protocolbuffers/protobuf/releases/download/v3.10.0/protobuf-cpp-3.10.0.tar.gz).
2. Navigate to the extracted Protobuf directory in a terminal.
3. Run `./configure`
4. Run `make && make check`
5. Run `sudo make install`

##### Compiling Protocol buffers message definitions
When you make a change to `message.proto` defnition file, you need to run this:

`protoc -I=./src/p2p --cpp_out=./src/p2p ./src/p2p/message.proto`

#### Run ldconfig
`sudo ldconfig`

This will update your library cache and avoid potential issues when running your compiled C++ program which links to newly installed libraries.

#### Install CMAKE
If you use apt, run `sudo apt install cmake` or follow [this](https://cmake.org/install/).

#### Build and run Hot Pocket
1. Navigate to hotpocket repo root.
1. Run `cmake .` (You only have to do this once)
1. Run `make` (Hot Pocket binary will be created as `./build/hpcore`)
1. Refer to [Running Hot Pocket](https://github.com/HotPocketDev/core/wiki/Running-Hot-Pocket) in the Wiki.

Refer to [Hot Pocket Wiki](https://github.com/HotPocketDev/core/wiki/Hot-Pocket-Wiki) for more info.

## Code structure
Code is divided into subsystems via namespaces.

**conf::** Handles contract configuration. Loads and holds the central configuration object. Used by most of the subsystems.

**crypto::** Handles cryptographic activities. Wraps libsodium and offers convenience functions.

**proc::** Handles contract process execution.

**usr::** Handles user connections and processing of user I/O with the smart contract. Makes use of **crypto** and **sock**.

**p2p::** Handles peer-to-peer connections and message exchange between nodes. Also handles smart contract node-party-line (npl) I/O. Makes use of **crypto** and **sock**.

**cons::** Handles consensus and proposal rounds. Makes use of **usr**, **p2p** and **proc**

**sock::** Handles generic web sockets functionality. Mainly acts as a wrapper for boost/beast.

**util::** Contains shared data structures/helper functions used by multiple subsystems.