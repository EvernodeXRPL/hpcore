#!/bin/bash

nodes=3
sudo ./cluster-create.sh $nodes

WD=`pwd`
# Setup initial state data for all nodes but one.
for (( i=1; i<$nodes; i++ ))
do

    sudo mkdir -p ./hpcluster/node$i/statehist/0/data/
    pushd ./hpcluster/node$i/statehist/0/data/
    >appbill.table
    $WD/examples/appbill/appbill --credit "65698fdee1b8fec4c1262f27f6fc94dd9cadf949bced42d12478e063f5751bc0" 10000
    popd
    #sudo cp -r ~/Downloads/big.mkv ~/hpcore/hpcluster/node$i/statehist/0/data/

done
