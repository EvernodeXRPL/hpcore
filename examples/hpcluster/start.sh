#!/bin/bash

# Runs the specified node contract with hpcore docker image.
# Usage (to run the node no. 1): ./start.sh 1

# Validate the node count arg.
if [ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
  echo "Starting docker container..."
else
  echo "Error: Please provide node ID to run."
  exit 1
fi

clusterloc=`dirname $0`
cd $clusterloc
clusterloc=$(pwd)
n=$1

# Create docker virtual network named 'hpnet'
# All nodes will communicate with each other via this network.
docker network create --driver bridge hpnet > /dev/null 2>&1

let pubport=8080+$n
# let peerport=22860+$n #Uncomment if peer port needs to be exposed to host.

# Mount the node<id> contract directory into hpcore docker container and run.
# We specify --network=hpnet so all nodes will communicate via 'hpnet' docker virtual network.
# We specify --name for each node so it will be the virtual dns name for each node.
docker run --rm -t -i --network=hpnet --name=node${n} \
    -p ${pubport}:${pubport} \
    # -p ${peerport}:${peerport} \ #Uncomment if peer port needs to be exposed to host.
    --mount type=bind,source=${clusterloc}/node${n},target=/contract \ # Mount the node directory.
    hpcore:latest run /contract