#!/bin/bash

hpcoredir=$(realpath ../..)
repo=hotpocketdev/hotpocket

# Prepare build context
tmp=$(mktemp -d)
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} $tmp/
strip $tmp/hpcore

# Ubuntu base image
docker build -t $repo:ubt.20.04 -f ./Dockerfile.ubt.20.04 $tmp/
rm -r $tmp/*

# NodeJs image
nodetmp=$(mktemp -d)
# Download and place the nodejs binary in the build context.
curl -fsSL -o $nodetmp/nodejs.tar.xz https://nodejs.org/dist/v14.17.3/node-v14.17.3-linux-x64.tar.xz
tar -xJvf $nodetmp/nodejs.tar.xz --strip-components=1 -C $nodetmp
cp $nodetmp/bin/node $tmp/
rm -r $nodetmp
docker build -t $repo:ubt.20.04-njs.14 -f ./Dockerfile.njs.14 $tmp

rm -r $tmp