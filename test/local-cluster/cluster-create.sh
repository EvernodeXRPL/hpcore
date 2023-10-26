#!/bin/bash
# Script to generate docker container clusters for local development testing.
# Generate contract sub-directories within "hpcluster" directory for the given no. of cluster nodes.
# Usage: To generate 5-node cluster:         ./cluster-create.sh 5
#        Specify log level (default: inf):   ./cluster-create.sh 5 dbg
#        Specify round time (default: 1000): ./cluster-create.sh 5 inf 2000

# Validate the node count arg.
if [ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
  echo "Generating a HotPocket cluster of ${1} node(s)..."
else
  echo "Error: Please provide number of nodes."
  exit 1
fi

ncount=$1
loglevel=$2
roundtime=$3
fallback_enabled=$4
hpcore=$(realpath ../..)
iprange="172.1.1"

# Contract can be set with 'export CONTRACT=<name>'. Defaults to nodejs echo contract.
if [ "$CONTRACT" = "cecho" ]; then # C echo contract
    echo "Using C echo contract."
    pushd $hpcore/examples/c_contract/ > /dev/null 2>&1
    gcc echo_contract.c -o echo_contract -Wall -Werror
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/c_contract/echo_contract"
    binary="echo_contract"

elif [ "$CONTRACT" = "nodefile" ]; then # nodejs file contract (uses BSON protocol)
    echo "Using nodejs file contract."
    pushd $hpcore/examples/nodejs_contract/ > /dev/null 2>&1
    npm install
    npm run build-file
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/nodejs_contract/dist/file-contract/index.js"
    binary="/usr/bin/node"
    binargs="index.js"
    
elif [ "$CONTRACT" = "diag" ]; then # Diagnostic contract
    echo "Using diagnostic contract."
    pushd $hpcore/examples/nodejs_contract/ > /dev/null 2>&1
    npm install
    npm run build-diag
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/nodejs_contract/dist/diagnostic-contract/index.js"
    binary="/usr/bin/node"
    binargs="index.js"

else # nodejs echo contract (default)
    echo "Using nodejs echo contract."
    pushd $hpcore/examples/nodejs_contract/ > /dev/null 2>&1
    npm install	
    npm run build-echo
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/nodejs_contract/dist/echo-contract/index.js"
    binary="/usr/bin/node"
    binargs="index.js"
fi

if [ "$loglevel" = "" ]; then
    loglevel=inf
fi
if [ "$roundtime" = "" ]; then
    roundtime=1000
fi
if [ "$fallback_enabled" != "true" ]; then
    fallback_enabled=false
fi

# Delete and recreate 'hpcluster' directory.
sudo rm -rf hpcluster > /dev/null 2>&1
mkdir hpcluster
clusterloc="./hpcluster"

pushd $clusterloc > /dev/null 2>&1

# Create contract directories for all nodes in the cluster.
for (( i=0; i<$ncount; i++ ))
do

    let n=$i+1
    let peerport=22860+$n
    let pubport=8080+$n

    # Create contract dir named "node<i>"
    ../bin/hpcore new "node${n}" > /dev/null 2>&1

    pushd ./node$n/cfg > /dev/null 2>&1

    # Use NodeJs to manipulate HP json configuration.

    mv hp.cfg tmp.json  # nodejs needs file extension to be .json

    # Collect each node pubkey and peer ports for later processing.

    pubkeys[i]=$(node -p "require('./tmp.json').node.public_key")

    # During hosting we use docker virtual dns instead of IP address.
    # So each node is reachable via 'node<id>' name.
    peers[i]="$iprange.${n}:${peerport}"
    
    # Update config.
    node_json=$(node -p "JSON.stringify({...require('./tmp.json').node, \
                    history: 'custom',\
                    history_config: {\
                        max_primary_shards: 4,\
                        max_raw_shards: 4\
                    }\
                }, null, 2)")

    contract_json=$(node -p "JSON.stringify({...require('./tmp.json').contract, 
                    id: '3c349abe-4d70-4f50-9fa6-018f1f2530ab', \
                    bin_path: '$binary', \
                    bin_args: '$binargs', \
                    environment: {}, \
                    consensus: { \
                        ...require('./tmp.json').contract.consensus, \
                        mode: 'public', \
                        roundtime: $roundtime \
                    }, \
                    npl: { \
                        mode: 'public' \
                    },\
                    fallback: { \
                        execute: $fallback_enabled \
                    }\
                }, null, 2)")

    mesh_json=$(node -p "JSON.stringify({...require('./tmp.json').mesh, \
                    port:${peerport}, \
                    peer_discovery: { \
                        enabled: true, \
                        interval: 10000 \
                    }
                }, null, 2)")
    user_json=$(node -p "JSON.stringify({...require('./tmp.json').user, \
                    port:${pubport}
                }, null, 2)")

    log_json=$(node -p "JSON.stringify({...require('./tmp.json').log, \
                    log_level: '$loglevel', \
                    loggers:['console', 'file'] \
                }, null, 2)")

    node -p "JSON.stringify({...require('./tmp.json'), \
                node: ${node_json},\
                contract: ${contract_json},\
                mesh: ${mesh_json},\
                user: ${user_json}, \
                log: ${log_json}, \
            }, null, 2)" > hp.cfg
    rm tmp.json

    popd > /dev/null 2>&1

    # Copy the contract files.
    eval "cp -r $copyfiles ./node$n/contract_fs/seed/state/"
done

# Function to generate JSON array string while skiping a given index.
function joinarr {
    arrname=$1[@]
    arr=("${!arrname}")
    skip=$2

    let prevlast=$ncount-2
    # Resetting prevlast if nothing is given to skip.
    if [ $skip -lt 0 ]
    then
        let prevlast=prevlast+1
    fi

    j=0
    str="["
    for (( i=0; i<$ncount; i++ ))
    do
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

# Loop through all nodes hp.cfg and inject peer and unl lists (skip self node for peers).
for (( j=0; j<$ncount; j++ ))
do
    let n=$j+1
    mypeers=$(joinarr peers $j)
    # Skip param is passed as -1 to stop skipping self pubkey.
    myunl=$(joinarr pubkeys -1)

    pushd ./node$n/cfg > /dev/null 2>&1
    mv hp.cfg tmp.json  # nodejs needs file extension to be .json
    contract_json=$(node -p "JSON.stringify({...require('./tmp.json').contract, unl:${myunl}}, null, 2)")
    mesh_json=$(node -p "JSON.stringify({...require('./tmp.json').mesh, known_peers:${mypeers}}, null, 2)")
    node -p "JSON.stringify({...require('./tmp.json'), contract:${contract_json}, mesh:${mesh_json}}, null, 2)" > hp.cfg
    rm tmp.json
    popd > /dev/null 2>&1
done

# Setup initial state data for all nodes.
for (( i=1; i<=$ncount; i++ ))
do

    mkdir -p ./node$i/contract_fs/seed/ > /dev/null 2>&1

    pushd ./node$i/contract_fs/seed/state/ > /dev/null 2>&1

    # Copy any more initial state files for testing.
    # cp ~/my_big_file .

    popd > /dev/null 2>&1

done

popd > /dev/null 2>&1

# Create docker virtual network named 'hpnet'
# All nodes will communicate with each other via this network.
docker network rm hpnet > /dev/null 2>&1
docker network create --driver=bridge --subnet=$iprange.0/24 --gateway=$iprange.254 hpnet > /dev/null 2>&1

echo "Cluster generated at ${clusterloc}"
echo "Use \"./cluster-start.sh <nodeid>\" to run each node."

exit 0