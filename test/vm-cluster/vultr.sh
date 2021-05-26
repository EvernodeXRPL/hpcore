#!/bin/bash
# Vultr API script

planid="vc2-1c-1gb" # $5/month
osid=387 # Ubuntu 20.04

# jq command is used for json manipulation.
if ! command -v jq &> /dev/null
then
    sudo apt-get install -y jq
fi
if ! command -v curl &> /dev/null
then
    sudo apt-get install -y curl
fi

configfile=config.json
if [ ! -f $configfile ]; then
    echo "config.json not found."
    exit 1
fi

apikey=$(jq -r ".vultr.api_key" $configfile)
if [ -z $apikey ]; then
    echo "Vultr api key not found."
    exit 1
fi
startscriptid=$(jq -c -r ".vultr.startup_script_id" $configfile)
sshkeyids=$(jq -c -r ".vultr.ssh_key_ids" $configfile)

# Common api calling functions.
function apicall() {
    if [ -z "$3" ]; then
        curl --silent "https://api.vultr.com/v2/$2" -X $1 -H "Authorization: Bearer $apikey" -H "Content-Type: application/json"
    else
        curl --silent "https://api.vultr.com/v2/$2" -X $1 -H "Authorization: Bearer $apikey" -H "Content-Type: application/json" --data "$3"
    fi
}
function apiget() {
    if [ -z "$2" ]; then
        apicall GET $1
    else
        apicall GET "$1/$2"
    fi
}
function apipost() {
    apicall POST $1 "$2"
}

# Vultr specific api calls.
function getplans() {
    apiget "plans"
}
function getregions() {
    apiget "regions"
}
function getoses() {
    apiget "os"
}
function getsshkeys() {
    apiget "ssh-keys"
}
function getstartscripts() {
    apiget "startup-scripts"
}
function createvm() {
    # vminfo=$(apipost "instances" '{"label":"'$1'", "region":"'$2'", "os_id":'$osid', "plan":"'$planid'", "hostname":"'$1'", "script_id":"'$startscriptid'", "sshkey_id":'$sshkeyids', "tag":"scriptvm", "backups":"disabled"}')
    vminfo='{"instance":{"id":"c26e52bb-033f-4ce2-8570-2584969083d8","os":"Ubuntu 20.04 x64","ram":1024,"disk":0,"main_ip":"0.0.0.0","vcpu_count":1,"region":"atl","plan":"vc2-1c-1gb","date_created":"2021-05-27T02:16:12+00:00","status":"pending","allowed_bandwidth":1000,"netmask_v4":"","gateway_v4":"0.0.0.0","power_status":"running","server_status":"none","v6_network":"","v6_main_ip":"","v6_network_size":0,"label":"testvm1","internal_ip":"","kvm":"","tag":"scriptvm","os_id":387,"app_id":0,"firewall_group_id":"","features":[],"default_password":"*2rQS[%#BsJeK)9o"}}'
    vmid=$(echo $vminfo | jq -r ".instance.id")
    vmip=$(echo $vminfo | jq -r ".instance.main_ip")
    if [ "$vmip" == "0.0.0.0" ]; then
        sleep 0.5
        vminfo=$(apiget "instances" $vmid)
        vmip=$(echo $vminfo | jq -r ".instance.main_ip")
    fi
    echo $vmip
}

#5cabcfea-2ec5-4b0b-bdaa-c17c15370dd9
createvm "testvm1" "atl"