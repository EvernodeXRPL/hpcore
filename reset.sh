#!/bin/bash

nodes=3
sudo ./cluster-create.sh $nodes

# Setup initial state data for all nodes but one.
for (( i=1; i<$nodes; i++ ))
do

    sudo mkdir -p ~/hpcore/hpcluster/node$i/statehist/0/data/
    #sudo cp -r ~/Downloads/big.mkv ~/hpcore/hpcluster/node$i/statehist/0/data/

done