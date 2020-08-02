#!/bin/bash

# Usage example:
# ./vmcli.sh resize B2s
# ./vmcli.sh stop
# ./vmcli.sh start

# List of vm domain names of the cluster must exist in vmlist.txt
readarray -t vmaddrs < vmlist.txt
vmcount=${#vmaddrs[@]}
resgroup=$(cat vmresgroup.txt)

mode=$1

set -e # exit on error

for (( i=0; i<$vmcount; i++ ))
do
    vmaddr=${vmaddrs[i]}
    let n=$i+1
    /bin/bash ./setup-vm.sh $mode $n $vmpass $vmaddr $hpcore &
done