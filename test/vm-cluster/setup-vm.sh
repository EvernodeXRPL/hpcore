#!/bin/bash

mode=$1
nodeid=$2
vmuser=$3
vmpass=$4
vmaddr=$5
basedir=$6
contdir=$7 # Contract directory

echo $nodeid. $vmaddr

if [ $mode = "new" ] || [ $mode = "update" ]; then
    echo "Uploading hp files to $basedir..."
    sshpass -p $vmpass scp -rp hpfiles $vmuser@$vmaddr:$basedir/
    echo "Upload finished."
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ]; then
    # Run hp setup script on the VM and download the generated hp.cfg
    echo "Configuring HP..."
    sshpass -p $vmpass ssh $vmuser@$vmaddr $basedir/hpfiles/setup-hp.sh $mode $basedir $contdir
    sshpass -p $vmpass scp $vmuser@$vmaddr:$contdir/cfg/hp.cfg ./cfg/node$nodeid.json
fi