#!/bin/bash

# Generate contract sub-directories within this script directory for the given no. of cluster nodes.
# Usage (to generate 8-node cluster): ./cluster-create.sh 8

# Validate the node count arg.
if [ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
  echo "Generating a Hot Pocket cluster of ${1} node(s)..."
else
  echo "Error: Please provide number of nodes."
  exit 1
fi

# Delete and recreate 'hpcluster' directory.
rm -rf hpcluster > /dev/null 2>&1
mkdir hpcluster
clusterloc="./hpcluster"

pushd $clusterloc > /dev/null 2>&1

# Create contract directories for all nodes in the cluster.
ncount=$1
for (( i=0; i<$ncount; i++ ))
do

    let n=$i+1
    let peerport=22860+$n
    let pubport=8080+$n

    # Create contract dir named "node<i>"
    ../build/hpcore new "node${n}" > /dev/null 2>&1

    pushd ./node$n/cfg > /dev/null 2>&1

    # Use NodeJs to manipulate HP json configuration.

    mv hp.cfg tmp.json  # nodejs needs file extension to be .json

    # Collect each node pubkey and peer ports for later processing.

    pubkeys[i]=$(node -p "require('./tmp.json').pubkeyhex")

    # During hosting we use docker virtual dns instead of IP address.
    # So each node is reachable via 'node<id>' name.
    peers[i]="node${n}:${peerport}"
    
    # Update contract config.
    node -p "JSON.stringify({...require('./tmp.json'), \
            binary: '/usr/local/bin/node', \
            binargs: './bin/contract.js', \
            peerport: ${peerport}, \
            pubport: ${pubport}, \
            roundtime: 1000, \
            loglevel: 'debug', \
            loggers:['console'] \
            }, null, 2)" > hp.cfg
    rm tmp.json

    # Generate ssl certs
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem \
        -subj "/C=AU/ST=ST/L=L/O=O/OU=OU/CN=localhost/emailAddress=hpnode${n}@example" > /dev/null 2>&1
    popd > /dev/null 2>&1

    # Copy the contract executable.
    mkdir ./node$n/bin
    cp ../examples/echocontract/contract.js ./node$n/bin/contract.js
done

# Function to generate JSON array string while skiping a given index.
function joinarr {
    arrname=$1[@]
    arr=("${!arrname}")
    skip=$2

    j=0
    str="["
    for (( i=0; i<$ncount; i++ ))
    do
        let prevlast=$ncount-2
        if [ "$i" != "$skip" ]
        then
            str="$str'${arr[i]}'"
            
            if [ $j -lt $prevlast ]
            then
                str="$str,"
            fi
            let j=j+1
        fi
    done
    str="$str]"

    echo $str
}

# Loop through all nodes hp.cfg and inject peer and unl lists (skip self node).
for (( j=0; j<$ncount; j++ ))
do
    let n=$j+1
    mypeers=$(joinarr peers $j)
    myunl=$(joinarr pubkeys $j)

    pushd ./node$n/cfg > /dev/null 2>&1
    mv hp.cfg tmp.json  # nodejs needs file extension to be .json
    node -p "JSON.stringify({...require('./tmp.json'),peers:${mypeers},unl:${myunl}}, null, 2)" > hp.cfg
    rm tmp.json
    popd > /dev/null 2>&1
done

popd > /dev/null 2>&1

# Create docker virtual network named 'hpnet'
# All nodes will communicate with each other via this network.
docker network create --driver bridge hpnet > /dev/null 2>&1

echo "Cluster generated at ${clusterloc}"
echo "Use \"./cluster-start.sh <nodeid>\" to run each node."

exit 0