#!/bin/bash
# Hot Pocket VM cluster management script.

# Usage examples:
# ./cluster.sh new
# ./cluster.sh update
# ./cluster.sh start 1
# ./cluster.sh start

conf=vmconfig.txt

# VM cluster parameters are in vmconfig.txt
source $conf

if [ -z "$vmuser" ] || [ -z "$vmpass" ] || [ -z "$contractpath" ]; then
    echo "vmuser=root" >> $conf
    echo "vmpass=<vm password>" >> $conf
    echo "contractpath=contract" >> $conf
    echo "Cluster configuration required in vmconfig.txt"
    exit 1
fi

# List of vm domain names of the cluster must exist in vmlist.txt
# (This list will be treated as the node numbers 1,2.3... from topmost address to the bottom)
readarray -t vmaddrs < vmlist.txt

vmcount=${#vmaddrs[@]}
mode=$1
let nodeid=$2-1

if [ "$vmuser" = "root" ]; then
    basedir=/$vmuser
else
    basedir=/home/$vmuser
fi
contdir=$basedir/$contractpath

hpcore=$(realpath ../..)

if [ "$mode" = "new" ] || [ "$mode" = "update" ] || [ "$mode" = "reconfig" ] || \
   [ "$mode" = "start" ] || [ "$mode" = "stop" ] || [ "$mode" = "check" ] || [ "$mode" = "log" ] || [ "$mode" = "kill" ] || \
   [ "$mode" = "ssh" ] || [ "$mode" = "reboot" ] || [ "$mode" = "dns" ] || [ "$mode" = "ssl" ] || [ "$mode" = "lcl" ]; then
    echo "mode: $mode ($contdir)"
else
    echo "Invalid command. [ new | update | reconfig" \
        " | start [N] | stop [N] | check [N] | log <N> | kill [N] | reboot <N> | ssh <N> <custom command>" \
        " | dns <N> <zerossl file> | ssl <N> | lcl ] expected."
    exit 1
fi

# Command modes:
# new - Install hot pocket dependencies and hot pocket with example contracts to each vm.
# update - Deploy updated hot pocket and example binaries into each vm.
# reconfig - Reconfigures the entire cluster using already uploaded HP binaries.
# start - Run hot pocket on specified vm node or entire cluster.
# stop - Gracefully stop hot pocket (if running) on specified vm node or entire cluster.
# check - Get hot pocket running process ids on specified vm node or entire cluster.
# log - Stream hot pocket console output log (if running) on specified vm node.
# kill - Force kill hot pocket (if running) on specified vm node or entire cluster.
# reboot - Reboot specified vm node.
# ssh - Open up an ssh terminal for the specified vm node.
# dns - Uploads given zerossl domain verification file to vm and starts http server for DNS check.
# ssl - Uploads matching zerossl certificate bundle from ~/Downloads/ to the contract.
# lcl - Displays the lcls of all nodes.

if [ $mode = "start" ]; then
    # Use the screen command so that the execution does not stop when ssh session ends.
    command="mkdir -p $contdir/screen && screen -c $contdir/hp.screenrc -m -d -L bash $contdir/run.sh"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$vmcount; i++ ))
        do
            vmaddr=${vmaddrs[i]}
            let nodeid=$i+1
            sshpass -p $vmpass ssh $vmuser@$vmaddr $command &
        done
        wait
    else
        vmaddr=${vmaddrs[$nodeid]}
        sshpass -p $vmpass ssh $vmuser@$vmaddr $command
    fi
    exit 0
fi

if [ $mode = "stop" ]; then
    command='kill -2 $(pidof hpcore)'
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$vmcount; i++ ))
        do
            vmaddr=${vmaddrs[i]}
            let nodeid=$i+1
            sshpass -p $vmpass ssh $vmuser@$vmaddr $command &
        done
        wait
    else
        vmaddr=${vmaddrs[$nodeid]}
        sshpass -p $vmpass ssh $vmuser@$vmaddr $command
    fi
    exit 0
fi

if [ $mode = "check" ]; then
    command='echo hpcore pid:$(pidof hpcore)  hpfs pid:$(pidof hpfs)  websocketd pid:$(pidof websocketd)  websocat pid:$(pidof websocat)'
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$vmcount; i++ ))
        do
            vmaddr=${vmaddrs[i]}
            let nodeid=$i+1
            echo "node"$nodeid":" $(sshpass -p $vmpass ssh $vmuser@$vmaddr $command) &
        done
        wait
    else
        vmaddr=${vmaddrs[$nodeid]}
        sshpass -p $vmpass ssh $vmuser@$vmaddr $command
    fi
    exit 0
fi

if [ $mode = "log" ]; then
    if [ $nodeid = -1 ]; then
        echo "Please specify node no. to view log stream."
        exit 1
    fi
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh -t $vmuser@$vmaddr screen -r -S hp_$(basename $contdir)
    exit 0
fi

if [ $mode = "kill" ]; then
    command='$basedir/kill.sh'
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$vmcount; i++ ))
        do
            vmaddr=${vmaddrs[i]}
            let nodeid=$i+1
            echo "node"$nodeid":" $(sshpass -p $vmpass ssh $vmuser@$vmaddr $command) &
        done
        wait
    else
        vmaddr=${vmaddrs[$nodeid]}
        sshpass -p $vmpass ssh $vmuser@$vmaddr $command
    fi
    exit 0
fi

if [ $mode = "reboot" ]; then
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh $vmuser@$vmaddr 'sudo reboot'
    exit 0
fi

if [ $mode = "ssh" ]; then
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh $vmuser@$vmaddr $3
    exit 0
fi

if [ $mode = "dns" ]; then
    if [[ $3 = "" ]]; then
        echo "Please provide zerossl domain verification txt file path."
        exit 1
    fi
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh $vmuser@$vmaddr 'mkdir -p $basedir/web80/.well-known/pki-validation'
    sshpass -p $vmpass scp $3 $vmuser@$vmaddr:$basedir/web80/.well-known/pki-validation/
    sshpass -p $vmpass ssh $vmuser@$vmaddr -t 'cd $basedir/web80 && sudo python -m SimpleHTTPServer 80'
    exit 0
fi

if [ $mode = "ssl" ]; then
    vmaddr=${vmaddrs[$nodeid]}

    unzip -d ~/Downloads/$vmaddr/ ~/Downloads/$vmaddr.zip || exit 1;
    pushd ~/Downloads/$vmaddr > /dev/null 2>&1
    mkdir certs
    cat certificate.crt <(echo) ca_bundle.crt > certs/tlscert.pem
    mv private.key certs/tlskey.pem
    popd > /dev/null 2>&1
    
    echo "Sending tls certs to the contract..."
    sshpass -p $vmpass scp ~/Downloads/$vmaddr/certs/* $vmuser@$vmaddr:$basedir/hpfiles/ssl/
    sshpass -p $vmpass ssh $vmuser@$vmaddr cp -rf $basedir/hpfiles/ssl/* $contdir/cfg/
    
    rm -r ~/Downloads/$vmaddr
    echo "Done"
    exit 0
fi

if [ $mode = "lcl" ]; then
    for (( i=0; i<$vmcount; i++ ))
    do
        vmaddr=${vmaddrs[i]}
        let nodeid=$i+1
        echo "node$nodeid:" $(sshpass -p $vmpass ssh $vmuser@$vmaddr ls -v $contdir/hist | tail -1) &
    done

    wait
    exit 0
fi

# All code below this will only execute in 'new', 'update' or 'reconfig' mode.
# Run setup/configuration of entire cluster.

# Copy required files to remote node hpfiles dir.

if [ $mode = "new" ] || [ $mode = "update" ]; then
    mkdir -p hpfiles/{bin,ssl,nodejs_contract}
    strip $hpcore/build/hpcore
    strip $hpcore/build/appbill
    cp $hpcore/build/hpcore hpfiles/bin/
    cp $hpcore/examples/nodejs_contract/{package.json,echo_contract.js,hp-contract-lib.js} \
        hpfiles/nodejs_contract/
fi

if [ $mode = "new" ]; then
    cp ../bin/{libfuse3.so.3,libblake3.so,fusermount3,websocketd,websocat,hpfs} hpfiles/bin/
    cp ./setup-hp.sh hpfiles/
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ]; then
    mkdir ./cfg > /dev/null 2>&1
fi

# Run vm setup for all nodes.
for (( i=0; i<$vmcount; i++ ))
do
    vmaddr=${vmaddrs[i]}
    let n=$i+1

    # Setup vm. (This will download hp.cfg in 'new' or 'reconfig' modes)
    /bin/bash ./setup-vm.sh $mode $n $vmuser $vmpass $vmaddr $basedir $contdir &
done

wait
rm -r hpfiles > /dev/null 2>&1

if [ $mode = "update" ]; then
    exit 0
fi

# All code below this will only execute in 'new' or 'reconfig' mode.
# Update downloaded hp.cfg files from all nodes to be part of the same UNL cluster.

# Locally update values of download hp.cfg files.
for (( i=0; i<$vmcount; i++ ))
do
    vmaddr=${vmaddrs[i]}
    let n=$i+1

    # Collect each node's pub key and peer address.
    pubkeys[i]=$(node -p "require('./cfg/node$n.json').pubkeyhex")
    peers[i]="$vmaddr:22860"
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

    node -p "JSON.stringify({...require('./cfg/node$n.json'), \
        binary:'/usr/bin/node', \
        binargs:'$basedir/hpfiles/nodejs_contract/echo_contract.js', \
        peers:${mypeers}, \
        unl:${myunl}, \
        roundtime: 2000, \
        loglevel: 'dbg', \
        loggers:['console'] \
        }, null, 2)" > ./cfg/node$n.cfg
done

for (( j=0; j<$vmcount; j++ ))
do
    # Upload local hp.cfg file back to remote vm.
    let n=$j+1
    vmaddr=${vmaddrs[j]}

    echo "Uploading configured hp.cfg..."
    sshpass -p $vmpass scp ./cfg/node$n.cfg $vmuser@$vmaddr:$contdir/cfg/hp.cfg &
done
wait

rm -r ./cfg
echo "Done."
