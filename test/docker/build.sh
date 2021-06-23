#!/bin/bash

hpcoredir=$(realpath ../..)
repo=hotpocketdev/hotpocket

# Build base Ubuntu image.
mkdir -p bin
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} ./bin/
strip ./bin/hpcore
docker build -t $repo:ubt.20.04 -f ./Dockerfile.ubt.20.04 ./bin
rm -r bin

# NodeJs image.
docker build -t $repo:ubt.20.04-njs.14 -f ./Dockerfile.ubt.20.04-njs.14 .