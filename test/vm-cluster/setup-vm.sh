#!/bin/bash

mode=$1
nodeid=$2
vmuser=$3
vmpass=$4
vmaddr=$5
basedir=$6
contdir=$7 # Contract directory

echo $nodeid. $vmaddr

echo "Uploading hp files to $basedir..."
sshpass -p $vmpass scp -rp hpfiles $vmuser@$vmaddr:$basedir/
echo "Upload finished."

if [ $mode = "new" ]; then
    # Run hp setup script on the VM and download the generated hp.cfg
    sshpass -p $vmpass ssh $vmuser@$vmaddr $basedir/hpfiles/setup-hp.sh $mode $basedir $contdir
    mkdir ./cfg > /dev/null 2>&1
    sshpass -p $vmpass scp $vmuser@$vmaddr:$contdir/cfg/hp.cfg ./cfg/node$nodeid.json
fi