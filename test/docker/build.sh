#!/bin/bash

hpcoredir=$(realpath ../..)
repo=hotpocketdev/hotpocket

# Prepare build context
mkdir -p bin
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} ./bin/
strip ./bin/hpcore

docker build -t $repo:ubt.20.04 -f ./Dockerfile.ubt.20.04 ./bin
docker build -t $repo:njs.14 -f ./Dockerfile.njs.14 ./bin

rm -r bin