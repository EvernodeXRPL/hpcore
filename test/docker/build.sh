#!/bin/bash

hpcoredir=$(realpath ../..)

mkdir -p bin
cp $hpcoredir/build/hpcore $hpcoredir/test/bin/{hpfs,hpws,libfuse3.so.3,libblake3.so,fusermount3} ./bin/
strip ./bin/hpcore
docker build -t hpcore:focal -f ./Dockerfile.hp-ubuntu-focal ./bin
rm -r bin