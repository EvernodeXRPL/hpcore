#!/bin/bash

# Usage:
# ./vmcli.sh <vmname> <command> <optional params>

vmname=$1
mode=$2
resgroup=$(cat vmresgroup.txt)

set -e # exit on error

if [ $mode = "info" ]; then
    az vm show --show-details -g $resgroup --name $vmname \
        --query "{name:name, size: hardwareProfile.vmSize, location:location, status:powerState}" -o json
elif [ $mode = "resize" ]; then
    az vm resize -g $resgroup --name $vmname --size Standard_$3
elif [ $mode = "stop" ]; then
    az vm stop -g $resgroup --name $vmname
    az vm deallocate -g $resgroup --name $vmname
elif [ $mode = "start" ]; then
    az vm start -g $resgroup --name $vmname
fi