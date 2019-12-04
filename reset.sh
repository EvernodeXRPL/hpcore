#!/bin/bash

sudo ./cluster-create.sh 3
sudo mkdir -p /home/ravin/hpcore/hpcluster/node1/statehist/0/data
sudo mkdir -p /home/ravin/hpcore/hpcluster/node2/statehist/0/data
sudo cp -r /home/ravin/Downloads/fuse-3.8.0/* /home/ravin/hpcore/hpcluster/node1/statehist/0/data
sudo cp -r /home/ravin/Downloads/fuse-3.8.0/* /home/ravin/hpcore/hpcluster/node2/statehist/0/data
