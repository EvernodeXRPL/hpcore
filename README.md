# Hot Pocket Consensus Engine

## What's here?
*In development*

A C++ version of hotpocket designed for production envrionments, original prototype here: https://github.com/codetsunami/hotpocket

## Libraries
* Crypto - Libsodium https://github.com/jedisct1/libsodium
* Websockets - Boost|Beast https://github.com/boostorg/beast
* RapidJSON - http://rapidjson.org
* Protocol - https://github.com/protocolbuffers/protobuf

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

1. Download and extract Protobuf 3.10.0 from [here](https://github.com/protocolbuffers/protobuf/releases/tag/v3.10.0).
2. Navigate to the extracted Protobuf directory in a terminal.
3. Run `./configure`
4. Run `make && make check`
5. Run `sudo make install`

#### Compile Protocol buffers
1. Run `protoc -I=./src/p2p --cpp_out=./src/p2p ./src/p2p/message.proto`
    Ex - For message protobuf 
            `protoc -I=./src/p2p --cpp_out=./src/p2p ./src/p2p/message.proto`
            
#### Run ldconfig
1. Run `sudo ldconfig`

This will update your library cache and avoid potential issues when running your compiled C++ program which links to newly installed libraries.

#### Install CMAKE
If you use apt, run `sudo apt install cmake`
Or follow [this](https://cmake.org/install/)

#### Build and run Hot Pocket
1. navigate to hotpocket repo root.
1. Run `cmake .` (You only have to do this once)
1. Run `make`
1. Run `./build/hpcore new ~/mycontract`. This will initialize a new contract directory `mycontract` in your home directory.
1. Take a look at `~/mycontract/cfg/hp.cfg`. This is your new contract config file. You can modify it according to your contract hosting requirements.
1. Optional: Run `./build/hpcore rekey ~/mycontract` to generate new public/private key pair.
1. Run `./build/hpcore run ~/mycontract` to run your smart contract (to do).

## Code structure
Code is divided into subsystems via namespaces. Some subsystems mentioned here are yet to be introduced.

#### conf
Handles contract configuration. Loads and holds the central configuration object. Used by most of the subsystems.

#### crypto
Handles cryptographic activities. Wraps libsodium and offers convinience functions.

#### proc
Handles contract process execution.

#### usr
Handles user connections and processing of user I/O with the smart contract. Makes use of **crypto** and **sock**.

#### ntn
Handles node-to-node connections and message exchange between nodes. Also handles smart contract node-party-line (npl) I/O. Makes use of **crypto** and **sock**.

#### cons
Handles consensus and proposal rounds. Makes use of **usr**, **ntn** and **proc**

#### sock
Handles generic web sockets functionality. Mainly acts as a wrapper for boost/beast.

#### shared
Contains shared data structures/helper functions used by multiple subsystems. Used by most of the subsystems.