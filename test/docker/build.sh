#!/bin/bash

hpcoredir=$(realpath ../..)
repo=hotpocketdev/hotpocket

# Build base Ubuntu image.
mkdir -p bin
cp $hpcoredir/build/hpcore $hpcoredir/test/bin/{hpfs,hpws,libfuse3.so.3,libblake3.so,fusermount3} ./bin/
strip ./bin/hpcore
docker build -t $repo:ubt.20.04 -f ./Dockerfile.ubt.20.04 ./bin
rm -r bin

# NodeJs image.
docker build -t $repo:ubt.20.04-njs.14 -f ./Dockerfile.ubt.20.04-njs.14 .