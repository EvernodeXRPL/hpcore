#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmaddr=$4
hpcore=$5

echo $nodeid. $vmaddr

echo "Uploading hp files..."
sshpass -f vmpass.txt scp -rp hpfiles geveo@$vmaddr:~/
echo "Upload finished."

if [ $mode = "new" ]; then
    # Run hp setup script on the VM and download the generated hp.cfg
    sshpass -f vmpass.txt ssh geveo@$vmaddr '~/hpfiles/setup-hp.sh && cd ~/hpfiles/nodejs_contract && npm install'
    sshpass -f vmpass.txt ssh geveo@$vmaddr 'echo sudo ~/hpfiles/bin/hpcore run ~/contract > ~/run.sh && sudo chmod +x ~/run.sh'
    mkdir ./cfg > /dev/null 2>&1
    sshpass -f vmpass.txt scp geveo@$vmaddr:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
fi