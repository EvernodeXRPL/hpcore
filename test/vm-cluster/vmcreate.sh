#!/bin/bash

# Usage example: ./vmcreate.sh hp1 australiaeast

# Azure vm creation script
# az login
# az account list
# az account set --subscription ''
# az account list-locations

vmname=$1
loc=$2
vmsize=Standard_B1s
vmpass=$(cat vmpass.txt)
resgroup=$(cat vmresgroup.txt)

set -e # exit on error

az vm create --name $vmname --resource-group $resgroup --size $vmsize \
--admin-username geveo --admin-password $vmpass --image UbuntuLTS --location $loc --generate-ssh-keys \
--public-ip-address-dns-name $vmname --tags $vmname

# HP peer port
az vm open-port --resource-group $resgroup --name $vmname --port 22860 --priority 900
# HP user port
az vm open-port --resource-group $resgroup --name $vmname --port 8080 --priority 901
# For DNS verification web server
az vm open-port --resource-group $resgroup --name $vmname --port 80 --priority 902

vmdns=$vmname.$loc.cloudapp.azure.com
echo $vmdns >> vmlist.txt
echo $vmdns " created and added to vmlist.txt"

# Stop the VM and downgrade disk storage to Standard SSD.
echo Downgrading OS disk...
az vm stop -g $resgroup --name $vmname
az vm deallocate -g $resgroup --name $vmname

diskid=$(az vm show -n $vmname -g $resgroup --query storageProfile.osDisk.managedDisk.id -o tsv)
az disk update --sku StandardSSD_LRS --ids $diskid

az vm start -g $resgroup --name $vmname

ssh-keyscan -H $vmdns >> ~/.ssh/known_hosts
echo Done.