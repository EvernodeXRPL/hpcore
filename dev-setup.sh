#!/bin/bash
# Usage ./dev-setup.sh
# Hot Pocket build environment setup script.

set -e # exit on error

sudo apt-get update
sudo apt-get install -y build-essential libssl-dev

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
# Copy the flatbuffers compiler
sudo cp flatc /usr/local/bin/flatc
sudo chmod +x /usr/local/bin/flatc
popd > /dev/null 2>&1
rm v1.12.0.tar.gz && rm -r flatbuffers-1.12.0

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
rm v1.0.3.tar.gz && sudo rm -r readerwriterqueue-1.0.3

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

# Library dependencies.
sudo apt-get install -y \
    libsodium-dev \
    sqlite3 libsqlite3-dev \
    libboost-stacktrace-dev \
    fuse3

# jq command (needed for remote cluster scripts)
sudo apt-get install -y jq

# NodeJs
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
# ncc build utility for nodejs compiled builds.
sudo npm i -g @vercel/ncc

# Update linker library cache.
sudo ldconfig

# Pop workdir
popd > /dev/null 2>&1
rm -r $workdir

# Build Hot Pocket
cmake .
make