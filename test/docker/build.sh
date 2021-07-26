#!/bin/bash
# Builds all the Hot Pocket docker images.

hpcoredir=$(realpath ../..)
img=hotpocketdev/hotpocket

# Prepare build context
tmp=$(mktemp -d)
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} $tmp/
strip $tmp/hpcore

hpversion=$($tmp/hpcore version | head -n 1)
# Remove the revision component from hp version to make up the image version.
imgversion=$(echo "${hpversion%.*}")

# Ubuntu base image
docker build -t $img:$imgversion-ubt.20.04 -f ./Dockerfile.ubt.20.04 $tmp/
rm -r $tmp/*

# NodeJs image
# Download and place the nodejs binary in the build context.
curl -fsSL -o $tmp/nodejs.tar.xz https://nodejs.org/dist/v14.17.3/node-v14.17.3-linux-x64.tar.xz
tar -xvJf $tmp/nodejs.tar.xz --strip-components=2 -C $tmp/ node-v14.17.3-linux-x64/bin/node
rm $tmp/nodejs.tar.xz
docker build -t $img:$imgversion-ubt.20.04-njs.14 -f ./Dockerfile.ubt.20.04-njs $tmp

rm -r $tmp