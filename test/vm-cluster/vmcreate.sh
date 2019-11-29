#!/bin/bash

# Azure vm creation.s
#az login
#az account list
#az account set --subscription ''

name=$1
loc=$2
vmpass=""
az vm create --name $name --resource-group HotPocket-ResGroup --size Standard_B1s --admin-username geveo --admin-password $vmpass --image UbuntuLTS --location $loc --generate-ssh-keys
az vm open-port --resource-group HotPocket-ResGroup --name $name --port 22860 --priority 900 && \
az vm open-port --resource-group HotPocket-ResGroup --name $name --port 8080 --priority 901
