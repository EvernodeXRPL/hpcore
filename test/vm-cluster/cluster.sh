#!/bin/bash

# Usage example: ./cluster.sh run 1

# VM login password must exist in vmpass.txt
vmpass=$(cat vmpass.txt)
# List vm IP addresses of the cluster must exist in iplist.txt
# (This list will be treated as the node numbers 1,2.3... from topmost IP to the bottom)
readarray -t vmips < iplist.txt

vmcount=${#vmips[@]}
mode=$1

hpcore=$(realpath ../..)

if [ "$mode" = "new" ] || [ "$mode" = "update" ] || [ "$mode" = "run" ] || [ "$mode" = "check" ] || \
   [ "$mode" = "monitor" ] || [ "$mode" = "kill" ] || [ "$mode" = "reboot" ] || [ "$mode" = "ssh" ] || \
   [ "$mode" = "dns" ] || [ "$mode" = "ssl" ]; then
    echo "mode: $mode"
else
    echo "Invalid command. [ new | update | run <N> | check <N> | monitor <N> | kill <N> | reboot <N> | ssh <N> <custom command> | dns <N> <zerossl file> | ssl <N> ] expected."
    exit 1
fi

# Command modes:
# new - Install hot pocket dependencies and hot pocket with example contracts to each vm.
# update - Deploy updated hot pocket and example binaries into each vm.
# run - Run hot pocket of specified vm node.
# check - Check hot pocket running status of specified vm node.
# monitor - Monitor streaming hot pocket console output (if running) of specified vm node.
# kill - Kill hot pocket (if running) of specified vm node.
# reboot - Reboot specified vm node.
# ssh - Open up an ssh terminal for the specified vm node.
# dns - Uploads given zerossl domain verification file to vm and starts http server for DNS check.
# ssl - Uploads matching zerossl certificate bundle from ~/Downloads/ to the contract.

if [ $mode = "run" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'nohup sudo ./hpcore run contract'
    sshpass -f vmpass.txt ssh geveo@$vmip 'tail -f nohup.out'
    exit 0
fi

if [ $mode = "check" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'echo hpcore pid:$(pidof hpcore)  hpfs pid:$(pidof hpfs)  websocketd pid:$(pidof websocketd)  websocat pid:$(pidof websocat)'
    exit 0
fi

if [ $mode = "monitor" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'tail -f nohup.out'
    exit 0
fi

if [ $mode = "kill" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'sudo kill $(pidof hpcore) > /dev/null 2>&1'
    sshpass -f vmpass.txt ssh geveo@$vmip 'sudo kill $(pidof hpfs) > /dev/null 2>&1'
    sshpass -f vmpass.txt ssh geveo@$vmip 'sudo kill $(pidof websocketd) > /dev/null 2>&1'
    sshpass -f vmpass.txt ssh geveo@$vmip 'sudo kill $(pidof websocat) > /dev/null 2>&1'
    exit 0
fi

if [ $mode = "reboot" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'sudo reboot'
    exit 0
fi

if [ $mode = "ssh" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip $3
    exit 0
fi

if [ $mode = "dns" ]; then
    if [[ $3 = "" ]]; then
        echo "Please provide zerossl domain verification txt file path."
        exit 1
    fi
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -f vmpass.txt ssh geveo@$vmip 'mkdir -p ~/web80/.well-known/pki-validation'
    sshpass -f vmpass.txt scp $3 geveo@$vmip:~/web80/.well-known/pki-validation/
    sshpass -f vmpass.txt ssh geveo@$vmip -t 'cd ~/web80 && sudo python -m SimpleHTTPServer 80'
    exit 0
fi

if [ $mode = "ssl" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}

    unzip -d ~/Downloads/$vmip/ ~/Downloads/$vmip.zip || exit 1;
    pushd ~/Downloads/$vmip > /dev/null 2>&1
    mkdir certs
    cat certificate.crt <(echo) ca_bundle.crt > certs/tlscert.pem
    mv private.key certs/tlskey.pem
    popd > /dev/null 2>&1
    
    echo "Sending tls certs to the contract..."
    sshpass -f vmpass.txt scp ~/Downloads/$vmip/certs/* geveo@$vmip:~/contract/cfg/
    
    rm -r ~/Downloads/$vmip
    exit 0
fi

mkdir ./cfg > /dev/null 2>&1

for (( i=0; i<$vmcount; i++ ))
do
    vmip=${vmips[i]}
    let n=$i+1
    /bin/bash ./setup-vm.sh $mode $n $vmpass $vmip $hpcore &
done

wait

if [ $mode = "update" ]; then
    exit 0
fi

# Following code will only be executed in 'new' mode.

for (( i=0; i<$vmcount; i++ ))
do
    vmip=${vmips[i]}
    let n=$i+1

    # Collect each node's pub key and peer address.
    pubkeys[i]=$(node -p "require('./cfg/node$n.json').pubkeyhex")
    peers[i]="$vmip:22860"
done

# Function to generate JSON array string while skiping a given index.
function joinarr {
    arrname=$1[@]
    arr=("${!arrname}")
    skip=$2

    j=0
    str="["
    for (( i=0; i<$vmcount; i++ ))
    do
        let prevlast=$vmcount-2
        if [ "$i" != "$skip" ]
        then
            str="$str'${arr[i]}'"
            
            if [ $j -lt $prevlast ]
            then
                str="$str,"
            fi
            let j=j+1
        fi
    done
    str="$str]"

    echo $str
}

# Loop through all nodes hp.cfg and inject peer and unl lists (skip self node).
for (( j=0; j<$vmcount; j++ ))
do
    let n=$j+1
    mypeers=$(joinarr peers $j)
    myunl=$(joinarr pubkeys $j)

    node -p "JSON.stringify({...require('./cfg/node$n.json'),binary:'/usr/bin/node',binargs:'/home/geveo/contract.js',peers:${mypeers},unl:${myunl},loggers:['console', 'file']}, null, 2)" > ./cfg/node$n.cfg

    # Copy local cfg file back to remote vm.
    vmip=${vmips[j]}
    sshpass -f vmpass.txt scp ./cfg/node$n.cfg geveo@$vmip:~/contract/cfg/hp.cfg
done
rm -r ./cfg