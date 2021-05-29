#!/bin/bash

mode=$1
nodeid=$2
sshuser=$3
hostaddr=$4
basedir=$5
contdir=$6 # Contract directory
hpfiles=$7 # HP files dir

echo $nodeid. $hostaddr

if [ $mode = "new" ] || [ $mode = "updatebin" ]; then
    echo "Uploading hp files to $basedir..."
    scp -o StrictHostKeyChecking=no -rp hpfiles $sshuser@$hostaddr:$basedir/
    echo "Upload finished."
fi

# Run hp setup script on the node and download the generated hp.cfg
if [ $mode = "new" ] || [ $mode = "reconfig" ]; then
    echo "Configuring HP..."
    ssh -o StrictHostKeyChecking=no $sshuser@$hostaddr $basedir/$hpfiles/setup-hp.sh $mode $basedir $contdir $hpfiles $hostaddr
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ] || [ $mode = "updateconfig" ]; then
    scp -o StrictHostKeyChecking=no $sshuser@$hostaddr:$contdir/cfg/hp.cfg ./cfg/node$nodeid.cfg
fi