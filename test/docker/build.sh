#!/bin/bash
# Builds all the Hot Pocket docker images.

hpcoredir=$(realpath ../..)
img=hotpocketdev/hotpocket
basefile="Dockerfile.ubt.20.04"
njsfile="Dockerfile.ubt.20.04-njs"

# Prepare build context
tmp=$(mktemp -d)
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} $tmp/
strip $tmp/hpcore

# Remove the revision component from hp version to make up the image version.
# hpversion=$($tmp/hpcore version | head -n 1)
# imgversion=$(echo "${hpversion%.*}")
imgversion="latest"

# Ubuntu base image
docker build -t $img:$imgversion-ubt.20.04 -f ./$basefile $tmp/
rm -r $tmp/*

# NodeJs image
# Download and place the nodejs binary in the build context.
curl -fsSL -o $tmp/nodejs.tar.xz https://nodejs.org/dist/v14.17.3/node-v14.17.3-linux-x64.tar.xz
tar -xvJf $tmp/nodejs.tar.xz --strip-components=2 -C $tmp/ node-v14.17.3-linux-x64/bin/node
rm $tmp/nodejs.tar.xz
cp ./$njsfile $tmp/
sed -i "s/%ver%/$imgversion/g" $tmp/$njsfile
docker build -t $img:$imgversion-ubt.20.04-njs.14 -f $tmp/$njsfile $tmp

rm -r $tmp