#!/bin/bash
vmpass=$(cat vmpass.txt)
readarray -t vmips < iplist.txt

vmcount=${#vmips[@]}
mode=$1

hpcore=$(realpath ../..)

if [ "$mode" = "new" ] || [ "$mode" = "run" ] || [ "$mode" = "update" ]; then
    echo ""
else
    echo "Invalid command. new | run | update expected."
    exit 1
fi

if [ $mode = "run" ]; then
    let nodeid=$2-1
    vmip=${vmips[$nodeid]}
    sshpass -p $vmpass ssh geveo@$vmip 'sudo ./hpcore run contract'
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

    node -p "JSON.stringify({...require('./cfg/node$n.json'),binary:'/usr/bin/node',binargs:'/home/geveo/contract.js',peers:${mypeers},unl:${myunl}}, null, 2)" > ./cfg/node$n.cfg

    # Copy local cfg file back to remote vm.
    vmip=${vmips[j]}
    sshpass -p $vmpass scp ./cfg/node$n.cfg geveo@$vmip:~/contract/cfg/hp.cfg
done
rm -r ./cfg