#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmip=$4
hpcore=$5

echo $nodeid. $vmip

# Copy required files to hpfiles dir.
mkdir -p hpfiles/{bin,nodejs_contract}

strip $hpcore/build/hpcore
cp $hpcore/build/hpcore hpfiles/bin/
cp $hpcore/examples/nodejs_contract/{package.json,echo_contract.js,hp-contract-lib.js} hpfiles/nodejs_contract/
if [ $mode = "new" ]; then
    cp ../bin/{libfuse3.so.3,libb2.so.1,fusermount3,websocketd,websocat,hpfs} hpfiles/bin/
    cp ./setup-hp.sh hpfiles/
fi

echo "Uploading hp files..."
sshpass -f vmpass.txt scp -rp hpfiles geveo@$vmip:~/
echo "Upload finished."

if [ $mode = "new" ]; then
    sshpass -f vmpass.txt ssh geveo@$vmip '~/hpfiles/setup-hp.sh && cd ~/hpfiles/nodejs_contract && npm install'
    sshpass -f vmpass.txt scp geveo@$vmip:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
fi

rm -r hpfiles