#!/bin/bash

mode=$1
nodeid=$2
sshuser=$3
sshpass=$4
hostaddr=$5
basedir=$6
contdir=$7 # Contract directory

echo $nodeid. $hostaddr

if [ $mode = "new" ] || [ $mode = "updatebin" ]; then
    echo "Uploading hp files to $basedir..."
    sshpass -p $sshpass scp -rp hpfiles $sshuser@$hostaddr:$basedir/
    echo "Upload finished."
fi

# Run hp setup script on the VM and download the generated hp.cfg
if [ $mode = "new" ] || [ $mode = "reconfig" ]; then
    echo "Configuring HP..."
    sshpass -p $sshpass ssh $sshuser@$hostaddr $basedir/hpfiles/setup-hp.sh $mode $basedir $contdir $hostaddr
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ] || [ $mode = "updateconfig" ]; then
    sshpass -p $sshpass scp $sshuser@$hostaddr:$contdir/cfg/hp.cfg ./cfg/node$nodeid.cfg
fi