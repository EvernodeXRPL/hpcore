#!/bin/bash
# Hot Pocket VM cluster management script.

# Usage examples:
# ./cluster.sh new
# ./cluster.sh update
# ./cluster.sh start 1
# ./cluster.sh start

# jq command is used for json manipulation.
if ! command -v jq &> /dev/null
then
    echo "jq command not found. Install with 'sudo apt-get install -y jq'"
    exit 1
fi

conf=vmconfig.json
if [ ! -f $conf ]; then
    # Create default config file.
    echo '{"vmuser":"root","vmpass":"","vms":[],"contracts":[{"name":"contract","config":{}}]}' | jq . > $conf
fi

vmuser=$(jq -r '.vmuser' $conf)

if [ "$vmuser" = "" ]; then
    echo "vmuser not specified."
    exit 1
elif [ "$CONTRACT" = "" ]; then
    CONTRACT=contract # Default contract name (can be set with 'export CONTRACT=<name>'').
fi

if [ "$vmuser" = "root" ]; then
    basedir=/$vmuser
else
    basedir=/home/$vmuser
fi

contconfig=$(jq -r ".contracts[] | select(.name == \"${CONTRACT}\") | .config" $conf)
if [ "$contconfig" = "" ]; then
    # Apply default config.
    contconfig="{public: {'port': 8080 }, peerport: 22860, 'contract': {'roundtime': 2000 }, 'log':{'loglevel': 'dbg', 'loggers':['console','file']}}"
fi

vmpass=$(jq -r '.vmpass' $conf)
readarray -t vmaddrs <<< $(jq -r '.vms[]' $conf)
contdir=$basedir/$CONTRACT
vmcount=${#vmaddrs[@]}
mode=$1
hpcore=$(realpath ../..)
let nodeid=$2-1

if [ "$mode" = "info" ] || [ "$mode" = "new" ] || [ "$mode" = "update" ] || [ "$mode" = "reconfig" ] || \
   [ "$mode" = "start" ] || [ "$mode" = "stop" ] || [ "$mode" = "check" ] || [ "$mode" = "log" ] || [ "$mode" = "kill" ] || \
   [ "$mode" = "ssh" ] || [ "$mode" = "reboot" ] || [ "$mode" = "dns" ] || [ "$mode" = "ssl" ] || [ "$mode" = "lcl" ] || [ "$mode" = "pubkey" ]; then
    echo "mode: $mode ($contdir)"
else
    echo "Invalid command. [ info | new | update | reconfig" \
        " | start [N] | stop [N] | check [N] | log <N> | kill [N] | reboot <N> | ssh <N>or<command>" \
        " | dns <N> <zerossl file> | ssl <N> | lcl | pubkey <N> ] expected."
    exit 1
fi

# Command modes:
# info - Displays information about current cluster configuration status.
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
# pubkey - Displays the pubkey on specified vm node or entire cluster.

if [ $mode = "info" ]; then
    echo "${vmaddrs[*]}" | tr ' ' '\n'
    echo $contconfig
    exit 0
fi

if [ $mode = "start" ]; then
    # Use the screen command so that the execution does not stop when ssh session ends.
    command="mkdir -p $contdir/screen && screen -c $contdir/hp.screenrc -m -d bash $contdir/start.sh"
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
    command="$contdir/stop.sh"
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
    command="$contdir/check.sh"
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
        echo "Please specify node no.."
        exit 1
    fi
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh -t $vmuser@$vmaddr screen -r -S hp_$(basename $contdir)
    exit 0
fi

if [ $mode = "kill" ]; then
    command="$contdir/kill.sh"
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
    if [ $nodeid = -1 ]; then
        echo "Please specify node no."
        exit 1
    fi
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh $vmuser@$vmaddr 'sudo reboot'
    exit 0
fi

if [ $mode = "ssh" ]; then
    if [ $nodeid = -1 ]; then
        if [ -n "$2" ]; then
            # Interprit second arg as a command to execute on all nodes.
            command=${*:2}
            echo "Executing '$command' on all nodes..."
            for (( i=0; i<$vmcount; i++ ))
            do
                vmaddr=${vmaddrs[i]}
                let nodeid=$i+1
                echo "node"$nodeid":" $(sshpass -p $vmpass ssh $vmuser@$vmaddr $command) &
            done
            wait
            exit 0
        else
            echo "Please specify node no. or command to execute on all nodes."
            exit 1
        fi
    else
        vmaddr=${vmaddrs[$nodeid]}
        sshpass -p $vmpass ssh -t $vmuser@$vmaddr "cd $contdir ; bash"
        exit 0
    fi
fi

if [ $mode = "dns" ]; then
    if [ $nodeid = -1 ]; then
        echo "Please specify node no."
        exit 1
    fi
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
    if [ $nodeid = -1 ]; then
        echo "Please specify node no."
        exit 1
    fi
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

if [ $mode = "pubkey" ]; then
    command="cat $contdir/cfg/hp.cfg | grep public_key | cut -d '\"' -f4"
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
    cp ../bin/{libfuse3.so.3,libblake3.so,fusermount3,hpws,hpfs} hpfiles/bin/
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
peerport=$(echo $contconfig | jq -r ".mesh.port")
for (( i=0; i<$vmcount; i++ ))
do
    vmaddr=${vmaddrs[i]}
    let n=$i+1

    # Collect each node's pub key and peer address.
    pubkeys[i]=$(jq -r ".node.public_key" ./cfg/node$n.cfg)
    peers[i]="$vmaddr:$peerport"
done

# Function to generate JSON array string while skiping a given index.
function joinarr {
    arrname=$1[@]
    arr=("${!arrname}")
    skip=$2

    let prevlast=$vmcount-2
    # Resetting prevlast if nothing is given to skip.
    if [ $skip -lt 0 ]
    then
        let prevlast=prevlast+1
    fi

    j=0
    str="["
    for (( i=0; i<$vmcount; i++ ))
    do
        if [ "$i" != "$skip" ]
        then
            str="$str\"${arr[i]}\""
            
            if [ $j -lt $prevlast ]
            then
                str="$str,"
            fi
            let j=j+1
        fi
    done
    str="$str]"

    echo $str # This returns the result.
}

# Loop through all nodes hp.cfg.
for (( j=0; j<$vmcount; j++ ))
do
    let n=$j+1

    # Prepare peer and unl lists (skip self node for peers).
    mypeers=$(joinarr peers $j)
    # Skip param is passed as -1 to stop skipping self pubkey.
    myunl=$(joinarr pubkeys -1)

    # Merge json contents to produce final contract config.
    echo "$(cat ./cfg/node$n.cfg)" \
        '{"contract": {"id": "3c349abe-4d70-4f50-9fa6-018f1f2530ab", "bin_path": "/usr/bin/node", "bin_args": "'$basedir'/hpfiles/nodejs_contract/echo_contract.js", "unl": '${myunl}'}}'\
        '{"mesh": {"known_peers": '${mypeers}'}}'\
        $contconfig \
        | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$n-merged.cfg
done

for (( j=0; j<$vmcount; j++ ))
do
    # Upload local hp.cfg file back to remote vm.
    let n=$j+1
    vmaddr=${vmaddrs[j]}

    echo "Uploading configured hp.cfg..."
    sshpass -p $vmpass scp ./cfg/node$n-merged.cfg $vmuser@$vmaddr:$contdir/cfg/hp.cfg &
done
wait

rm -r ./cfg
echo "Done."
