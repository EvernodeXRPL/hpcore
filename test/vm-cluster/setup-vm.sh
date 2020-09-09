#!/bin/bash

mode=$1
nodeid=$2
vmuser=$3
vmpass=$4
vmaddr=$5
hpcore=$6

echo $nodeid. $vmaddr

echo "Uploading hp files..."
sshpass -p $vmpass scp -rp hpfiles $vmuser@$vmaddr:~/
echo "Upload finished."

if [ $mode = "new" ]; then
    # Run hp setup script on the VM and download the generated hp.cfg
    sshpass -p $vmpass ssh $vmuser@$vmaddr '~/hpfiles/setup-hp.sh && cd ~/hpfiles/nodejs_contract && npm install'
    sshpass -p $vmpass ssh $vmuser@$vmaddr 'echo sudo ~/hpfiles/bin/hpcore run ~/contract > ~/run.sh && sudo chmod +x ~/run.sh'
    sshpass -p $vmpass ssh $vmuser@$vmaddr 'echo sudo kill $(pidof hpfs) $(pidof websocketd) $(pidof websocat) > ~/kill.sh && sudo chmod +x ~/kill.sh'
    mkdir ./cfg > /dev/null 2>&1
    sshpass -p $vmpass scp $vmuser@$vmaddr:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
fi