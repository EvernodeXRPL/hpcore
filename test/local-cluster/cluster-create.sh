#!/bin/bash
# Script to generate docker container clusters for local development testing.
# Generate contract sub-directories within "hpcluster" directory for the given no. of cluster nodes.
# Usage: To generate 5-node cluster:         ./cluster-create.sh 5
#        Specify log level (default: inf):   ./cluster-create.sh 5 dbg
#        Specify round time (default: 1000): ./cluster-create.sh 5 inf 2000

# Validate the node count arg.
if [ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
  echo "Generating a Hot Pocket cluster of ${1} node(s)..."
else
  echo "Error: Please provide number of nodes."
  exit 1
fi

ncount=$1
loglevel=$2
roundtime=$3
hpcore=$(realpath ../..)

# Contract can be set with 'export CONTRACT=<name>'. Defaults to nodejs echo contract.
if [ "$CONTRACT" = "cecho" ]; then # C echo contract
    echo "Using C echo contract."
    pushd $hpcore/examples/c_contract/ > /dev/null 2>&1
    gcc echo_contract.c -o echo_contract
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/c_contract/echo_contract"
    binary="/contract/bin/echo_contract"

elif [ "$CONTRACT" = "nodefile" ]; then # nodejs file contract (uses BSON protocol)
    echo "Using nodejs file contract."
    pushd $hpcore/examples/nodejs_contract/ > /dev/null 2>&1
    npm install
    popd > /dev/null 2>&1
    copyfiles="$hpcore/examples/nodejs_contract/{node_modules,package.json,hp-contract-lib.js,file_contract.js}"
    binary="/usr/local/bin/node"
    binargs="/contract/bin/file_contract.js"

else # nodejs echo contract (default)
    echo "Using nodejs echo contract."
    copyfiles="$hpcore/examples/nodejs_contract/{package.json,hp-contract-lib.js,echo_contract.js}"
    binary="/usr/local/bin/node"
    binargs="/contract/bin/echo_contract.js"
fi

if [ "$loglevel" = "" ]; then
    loglevel=inf
fi
if [ "$roundtime" = "" ]; then
    roundtime=1000
fi

# Delete and recreate 'hpcluster' directory.
rm -rf hpcluster > /dev/null 2>&1
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
    peers[i]="node${n}:${peerport}"
    
    # Update contract config.
    touch contract.json
    touch public.json
    node -p "JSON.stringify({...require('./tmp.json').contract}, null, 2)" > contract.json
    node -p "JSON.stringify({...require('./tmp.json').public}, null, 2)" > public.json
    node -p "JSON.stringify({...require('./tmp.json'), \
            contract: { \
                ...require('./contract.json'), \
                id: '3c349abe-4d70-4f50-9fa6-018f1f2530ab', \
                bin_path: '$binary', \
                bin_args: '$binargs', \
                roundtime: $roundtime, \
                appbill: { \
                    mode: '', \
                    bin_args: '' \
                }, \
            }, \
            peerport: ${peerport}, \
            public: {
                ...require('./public.json'), \
                port: ${pubport}, \
            }, \
            log: {\
                loglevel: '$loglevel', \
                loggers:['console', 'file'] \
            }\
            }, null, 2)" > hp.cfg
    rm tmp.json
    rm contract.json
    rm public.json

    # Generate ssl certs
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem \
        -subj "/C=AU/ST=ST/L=L/O=O/OU=OU/CN=localhost/emailAddress=hpnode${n}@example" > /dev/null 2>&1
    popd > /dev/null 2>&1

    # Copy the contract files and appbill.
    mkdir ./node$n/bin
    eval "cp -r $copyfiles ./node$n/bin/"
    cp ../bin/appbill ./node$n/bin/
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
    touch contract.json
    node -p "JSON.stringify({...require('./tmp.json').contract, unl:${myunl}}, null, 2)" > contract.json
    node -p "JSON.stringify({...require('./tmp.json'), contract:{...require('./contract.json')}, peers:${mypeers}}, null, 2)" > hp.cfg
    rm tmp.json
    rm contract.json
    popd > /dev/null 2>&1
done

# Setup initial state data for all nodes.
for (( i=1; i<=$ncount; i++ ))
do

    mkdir -p ./node$i/state/seed > /dev/null 2>&1

    pushd ./node$i/state/seed/ > /dev/null 2>&1
    
    # Load credit balance for user for appbill testing purposes.
    >appbill.table
    ../../../../bin/appbill --credit "705bf26354ee4c63c0e5d5d883c07cefc3196d049bd3825f827eb3bc23ead035" 10000

    # Copy any more initial state files for testing.
    # cp ~/my_big_file .

    popd > /dev/null 2>&1

done

popd > /dev/null 2>&1

# Create docker virtual network named 'hpnet'
# All nodes will communicate with each other via this network.
docker network create --driver bridge hpnet > /dev/null 2>&1

echo "Cluster generated at ${clusterloc}"
echo "Use \"./cluster-start.sh <nodeid>\" to run each node."

exit 0