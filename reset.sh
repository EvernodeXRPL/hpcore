#!/bin/bash

sudo ./cluster-create.sh 3
sudo mkdir -p /home/geveodev/hpcore/hpcluster/node1/statehist/0/data
sudo mkdir -p /home/geveodev/hpcore/hpcluster/node2/statehist/0/data/

sudo cp -r /home/geveodev/Downloads/fuse-3.8.0/* /home/geveodev/hpcore/hpcluster/node1/statehist/0/data
sudo cp -r /home/geveodev/Downloads/fuse-3.8.0/* /home/geveodev/hpcore/hpcluster/node2/statehist/0/data

