#!/bin/bash

hpcoredir=$(realpath ../..)
repo=hotpocketdev/hotpocket

# Prepare build context
mkdir -p bin
cp $hpcoredir/build/{hpcore,appbill} $hpcoredir/test/bin/{hpfs,hpws,libblake3.so} ./bin/
strip ./bin/hpcore

docker build -t $repo:buster -f ./Dockerfile.buster ./bin
docker build -t $repo:njs.14 -f ./Dockerfile.njs.14 ./bin

rm -r bin