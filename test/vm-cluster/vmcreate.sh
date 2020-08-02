#!/bin/bash

# Usage example: ./vmcreate.sh hp1 australiaeast

# Azure vm creation script
# az login
# az account list
# az account set --subscription ''
# az account list-locations

name=$1
loc=$2
vmsize=Standard_B1s
vmpass=$(cat vmpass.txt)
resgroup=$(cat vmresgroup.txt)

set -e # exit on error

az vm create --name $name --resource-group $resgroup --size $vmsize \
--admin-username geveo --admin-password $vmpass --image UbuntuLTS --location $loc --generate-ssh-keys \
--public-ip-address-dns-name $name

# HP peer port
az vm open-port --resource-group $resgroup --name $name --port 22860 --priority 900
# HP user port
az vm open-port --resource-group $resgroup --name $name --port 8080 --priority 901
# For DNS verification web server
az vm open-port --resource-group $resgroup --name $name --port 80 --priority 902

vmdns=$name.$loc.cloudapp.azure.com
echo $vmdns >> vmlist.txt
echo $vmdns " created and added to vmlist.txt"