#!/bin/bash

nodes=3
sudo ./cluster-create.sh $nodes
WD=`pwd`
# Setup initial state data for all nodes but one.
for (( i=1; i<$nodes; i++ ))
do
    
    sudo mkdir -p ~/hpcore/hpcluster/node$i/statehist/0/data/
    pushd ~/hpcore/hpcluster/node$i/statehist/0/data/
    >appbill.table
    $WD/build/appbill --credit 705bf26354ee4c63c0e5d5d883c07cefc3196d049bd3825f827eb3bc23ead035 10000
    popd
    #sudo cp -r ~/Downloads/big.mkv ~/hpcore/hpcluster/node$i/statehist/0/data/

done
