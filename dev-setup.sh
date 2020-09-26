#!/bin/bash
# Usage ./dev-setup.sh
# Ubuntu 18.04 hpcore build environment setup script.

sudo apt-get update
sudo apt-get install -y build-essential

workdir=~/hpcore-setup

mkdir $workdir
pushd $workdir > /dev/null 2>&1

# CMAKE
cmake=cmake-3.16.0-rc3-Linux-x86_64
wget https://github.com/Kitware/CMake/releases/download/v3.16.0-rc3/$cmake.tar.gz
tar -zxvf $cmake.tar.gz
sudo cp -r $cmake/bin/* /usr/local/bin/
sudo cp -r $cmake/share/* /usr/local/share/
rm $cmake.tar.gz && rm -r $cmake

# Libsodium
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
tar -zxvf libsodium-1.0.18-stable.tar.gz
pushd libsodium-stable > /dev/null 2>&1
./configure && make
sudo make install
popd > /dev/null 2>&1
rm libsodium-1.0.18-stable.tar.gz && rm -r libsodium-stable

# Blake3
git clone https://github.com/BLAKE3-team/BLAKE3.git
pushd BLAKE3/c > /dev/null 2>&1
gcc -shared -fPIC -O3 -o libblake3.so blake3.c blake3_dispatch.c blake3_portable.c \
    blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S \
    blake3_avx512_x86-64_unix.S
sudo cp blake3.h /usr/local/include/
sudo cp libblake3.so /usr/local/lib/
popd > /dev/null 2>&1
sudo rm -r BLAKE3

# jsoncons
wget https://github.com/danielaparker/jsoncons/archive/v0.153.3.tar.gz
tar -zxvf v0.153.3.tar.gz
pushd jsoncons-0.153.3 > /dev/null 2>&1
sudo cp -r include/jsoncons /usr/local/include/
sudo mkdir -p /usr/local/include/jsoncons_ext/
sudo cp -r include/jsoncons_ext/bson /usr/local/include/jsoncons_ext/
popd > /dev/null 2>&1
rm v0.153.3.tar.gz && rm -r jsoncons-0.153.3

# Flatbuffers
wget https://github.com/google/flatbuffers/archive/v1.12.0.tar.gz
tar -zxvf v1.12.0.tar.gz
pushd flatbuffers-1.12.0 > /dev/null 2>&1
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
make
sudo cp -r include/flatbuffers /usr/local/include/
popd > /dev/null 2>&1
rm v1.12.0.tar.gz && rm -r flatbuffers-1.12.0

# libfuse
sudo apt-get install -y meson ninja-build pkg-config
wget https://github.com/libfuse/libfuse/archive/fuse-3.8.0.tar.gz
tar -zxvf fuse-3.8.0.tar.gz
pushd libfuse-fuse-3.8.0 > /dev/null 2>&1
mkdir build
pushd build > /dev/null 2>&1
meson .. && ninja
sudo ninja install
popd > /dev/null 2>&1
popd > /dev/null 2>&1
rm fuse-3.8.0.tar.gz && rm -r libfuse-fuse-3.8.0

# Reader-Writer queue
wget https://github.com/cameron314/readerwriterqueue/archive/v1.0.3.tar.gz
tar -zxvf v1.0.3.tar.gz
pushd readerwriterqueue-1.0.3 > /dev/null 2>&1
mkdir build
pushd build > /dev/null 2>&1
cmake ..
sudo make install
popd > /dev/null 2>&1
popd > /dev/null 2>&1
rm v1.0.3.tar.gz && rm -r readerwriterqueue-1.0.3

# Concurrent queue
wget https://github.com/cameron314/concurrentqueue/archive/1.0.2.tar.gz
tar -zxvf 1.0.2.tar.gz
pushd concurrentqueue-1.0.2 > /dev/null 2>&1
sudo cp concurrentqueue.h /usr/local/include/
popd > /dev/null 2>&1
rm 1.0.2.tar.gz && rm -r concurrentqueue-1.0.2

# Plog
wget https://github.com/SergiusTheBest/plog/archive/1.1.5.tar.gz
tar -zxvf 1.1.5.tar.gz
pushd plog-1.1.5 > /dev/null 2>&1
sudo cp -r include/plog /usr/local/include/
popd > /dev/null 2>&1
rm 1.1.5.tar.gz && rm -r plog-1.1.5

# Boost stacktrace
sudo apt-get install -y libboost-stacktrace-dev

# Update linker library cache.
sudo ldconfig

# Pop workdir
popd > /dev/null 2>&1

# Build Hot Pocket
cmake .
make