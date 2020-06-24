# Hot Pocket Consensus Engine

## What's here?
*In development*

A C++ version of hotpocket designed for production envrionments, original prototype here: https://github.com/codetsunami/hotpocket

[Hot Pocket Wiki](https://github.com/HotPocketDev/core/wiki)

## Libraries
* Crypto - Libsodium https://github.com/jedisct1/libsodium
* Websockets - Server: [Websocketd (forked)](https://github.com/codetsunami/websocketd) | Client: [Websocat](https://github.com/vi/websocat) | Pipe: [netcat (OpenBSD)](https://man.openbsd.org/nc.1)
* RapidJSON - http://rapidjson.org
* P2P Protocol - https://google.github.io/flatbuffers
* Fuse filesystem - https://github.com/libfuse/libfuse
* Boost - https://www.boost.org

## Steps to setup Hot Pocket (For Ubuntu/Debian)

#### Install CMAKE 3.16
1. Download and extract [cmake-3.16.0-rc3-Linux-x86_64.tar.gz](https://github.com/Kitware/CMake/releases/download/v3.16.0-rc3/cmake-3.16.0-rc3-Linux-x86_64.tar.gz)
2. Navigate into the extracted directory in a terminal.
3. Run `sudo cp -r bin/* /usr/local/bin/`
4. Run `sudo cp -r share/* /usr/local/share/`

#### Install Libsodium
Instructions are based on [this](https://libsodium.gitbook.io/doc/installation).

1. Download and extract Libsodium 1.0.18 from [here](https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz).
2. Navigate to the extracted libsodium directory in a terminal.
3. Run `./configure && make && make check`
4. Run `sudo make install`

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

#### Install FlatBuffers
Instructions are based on [this](https://google.github.io/flatbuffers/).

1. Clone the git respository into a new directory from [here](https://github.com/google/flatbuffers).
2. Build with CMake
```
git clone https://github.com/google/flatbuffers.git
cd flatbuffers
cmake -G "Unix Makefiles"
make
```
3. Run `sudo cp -r include/flatbuffers /usr/local/include/`
4. Run `sudo snap install flatbuffers --edge`

##### Compiling FlatBuffers message definitions
Example: When you make a change to `p2pmsg_content_.fbc` defnition file, you need to run this:

`flatc -o src/msg/fbuf/ --gen-mutable --cpp src/msg/fbuf/p2pmsg_content.fbs`

#### Install libfuse
1. `sudo apt-get install -y meson ninja-build pkg-config`
2. Download [libfuse 3.8](https://github.com/libfuse/libfuse/releases/download/fuse-3.8.0/fuse-3.8.0.tar.xz) and extract.
3. `mkdir build; cd build`
4. `meson .. && ninja`
6. `sudo ninja install`

#### Run ldconfig
`sudo ldconfig`

This will update your linker library cache and avoid potential issues when running your compiled C++ program which links to newly installed libraries.

#### Build and run Hot Pocket
1. Navigate to hotpocket repo root.
1. Run `cmake .` (You only have to do this once)
1. Run `make` (Hot Pocket binary will be created as `./build/hpcore`)
1. Refer to [Running Hot Pocket](https://github.com/HotPocketDev/core/wiki/Running-Hot-Pocket) in the Wiki.

Refer to [Hot Pocket Wiki](https://github.com/HotPocketDev/core/wiki) for more info.

## Code structure
Code is divided into subsystems via namespaces.

**conf::** Handles contract configuration. Loads and holds the central configuration object. Used by most of the subsystems.

**crypto::** Handles cryptographic activities. Wraps libsodium and offers convenience functions.

**sc::** Handles smart contract process execution and managing user/SC I/O and npl I/O. Makes use of **usr**, **p2p** and **hpfs**.

**usr::** Handles user connections. Makes use of **crypto** and **comm**.

**p2p::** Handles peer-to-peer connections and message exchange between nodes. Makes use of **crypto** and **comm**.

**cons::** Handles consensus and proposal rounds. Makes use of **usr**, **p2p** and **sc**

**comm::** Handles generic web sockets communication functionality. Mainly acts as a wrapper for websocketd/websocat.

**util::** Contains shared data structures/helper functions used by multiple subsystems.

**hpfs::** [hpfs](https://github.com/HotPocketDev/hpfs) state management client helpers.