#!/bin/bash

# Usage example: ./vmcreate.sh hp1 aueast

# Azure vm creation script
# az login
# az account list
# az account set --subscription ''
# az account list-locations

name=$1
loc=$2
vmsize=Standard_B1s
vmpass=$(cat vmpass.txt)
resgroup=HotPocket-ResGroup

az vm create --name $name --resource-group $resgroup --size $vmsize --admin-username geveo --admin-password $vmpass --image UbuntuLTS --location $loc --generate-ssh-keys
az vm open-port --resource-group $resgroup --name $name --port 22860 --priority 900 && \
az vm open-port --resource-group $resgroup --name $name --port 8080 --priority 901

vmip=$(az vm show -d -g $resgroup -n $name --query publicIps -o tsv)
echo $vmip >> iplist.txt
echo $vmip "created and added to iplist.txt"