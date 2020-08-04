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
    # Gracefully shutdown and then deallocate.
    az vm stop -g $resgroup --name $vmname > /dev/null 2>&1
    az vm deallocate -g $resgroup --name $vmname

elif [ $mode = "start" ]; then
    az vm start -g $resgroup --name $vmname

elif [ $mode = "delete" ]; then

    echo Deleting vm $vmname...
    az resource delete -g ${resgroup} -n $vmname --resource-type "Microsoft.Compute/virtualMachines"

    # Get list of resources with specific tag
    reslist=`az resource list --tag $vmname`
    rescount=`echo $reslist | jq length`

    # Delete resources
    for((i=0; i<$rescount; i++)); do
        # Get $i th resource name and type
        resname=`echo $reslist | jq .[$i].name | tr -d '"'`
        restype=`echo $reslist | jq .[$i].type | tr -d '"'`
        
        echo Deleting $resname...
        az resource delete -g ${resgroup} -n ${resname} --resource-type ${restype}
    done
fi