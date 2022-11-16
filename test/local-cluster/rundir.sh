#!/bin/bash

# Runs the specified contract directory with hpcore docker image.
# This script assumes you already have the hpcore docker image and 'hpnet' virtual docker network.
# Usage: ./rundir.sh <dir path>

# Validate the node count arg.
if [ -z "$1" ]; then
  echo "Error: Please provide contract directory to run."
  exit 1
else
  echo "Starting docker container..."
fi

dir=$(realpath $1)
dirname=$(basename  $dir)
n=$1
hpversion=0.6.0

let pubport=8080

# Mount the directory $dir into hpcore docker container and run.
# We specify --network=hpnet so all nodes will communicate via 'hpnet' docker virtual network.
# We specify --name for each node so it will be the virtual dns name for each node.
docker run --rm -t -i --network=hpnet --name=hp_$dirname \
    -p ${pubport}:${pubport} \
    --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
    --mount type=bind,source=$dir,target=/contract \
    hpcore:${hpversion} run /contract