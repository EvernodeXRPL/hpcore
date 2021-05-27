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

# Common api calling function. (params: httpmethod, endpoint, bodyparams)
function apicall() {
    local url="https://api.vultr.com/v2/$2"
    local _result=""
    if [ -z "$3" ]; then
        _result=$(curl --silent "$url" -X $1 -H "Authorization: Bearer $apikey" -H "Content-Type: application/json" -w "\n%{http_code}")
    else
        _result=$(curl --silent "$url" -X $1 -H "Authorization: Bearer $apikey" -H "Content-Type: application/json" -w "\n%{http_code}" --data "$3")
    fi
    
    local _parts
    readarray -t _parts <<<"$_result" # break parts by new line.
    if [[ ${_parts[1]} == 2* ]]; then # Check for 2xx status code.
        [ ! -z "${_parts[0]}" ] && echo ${_parts[0]} # Return api output if there is any.
    else
        >&2 echo "Error on $1 $url code:${_parts[1]} body:${_parts[0]}"
        exit 1
    fi
}
function apiget() {
    if [ -z "$2" ]; then
        apicall GET $1
    else
        apicall GET "$1/$2"
    fi
}
function apigetquery() {
    apicall GET $1?$2
}
function apipost() {
    apicall POST $1 "$2"
}
function apidelete() {
    apicall DELETE "$1/$2"
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

# Creates a vm. (params: groupname, vmname, regionid)
function createvm() {
    local _vminfo=$(apipost "instances" '{"tag":"'$1'", "label":"'$2'", "region":"'$3'", "os_id":'$osid', "plan":"'$planid'", "hostname":"'$2'", "script_id":"'$startscriptid'", "sshkey_id":'$sshkeyids', "backups":"disabled"}')
    [ -z "$_vminfo" ] && exit 1
    local _vmid=$(echo $_vminfo | jq -r ".instance.id")
    local _vmip=$(echo $_vminfo | jq -r ".instance.main_ip")
    for (( i=0; i<20; i++ ))
    do
        if [ "$_vmip" == "0.0.0.0" ]; then
            sleep 1
            _vminfo=$(apiget "instances" $_vmid)
            _vmip=$(echo $_vminfo | jq -r ".instance.main_ip")
        else
            break
        fi
    done
    echo $2": "$_vmip
}

# Deletes a vm. (params: id)
function deletevm() {
    echo "Deleting vm "$1"..."
    apidelete "instances" $1
}

# Returns space-delimited list of vm ids in specified group. (params: groupname)
function getgroupvmids() {
    [ -z "$1" ] && >&2 echo "getgroupvmids: Group name not specified." && exit 1
    local _list=$(apigetquery "instances" "tag=$1")
    [ -z "$_list" ] && exit 1
    local _ids=$(echo $_list | jq -r ".instances | .[] | .id")
    echo $_ids
}

# Deletes a group of vms. (params: groupname)
function deletevmgroup() {
    echo "Deleting all vms in group '"$1"'..."
    local _ids=$(getgroupvmids "$1")
    [ -z "$_ids" ] && exit 1
    local _arr
    readarray -d " " -t _arr <<<"$_ids" # break parts by space character.
    echo ${#_arr[@]}" vms found to delete..."
    for id in "${_arr[@]}"
    do
        deletevm $id &
    done
    wait
    echo "Done."
}
function createvmgroup() {
    echo "Creating "$2" vms in group '"$1"'..."
    local num=""
    for (( i=1; i<=$2; i++ ))
    do
        num=$(printf "%03d" $i) # Pad left with 3 zeros.
        createvm "$1" "$1$num" "atl" &
    done
    wait
    echo "Done."
}

# createvmgroup "testb" 3
# deletevmgroup "testb"