#!/bin/bash
# Hot Pocket VM cluster management script.

# Usage examples:
# ./cluster.sh new
# ./cluster.sh updatebin
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
if [ "$contconfig" = "" ] || [ "$contconfig" = "{}" ]; then
    # Apply default config.
    contconfig="{\"user\": {\"port\": 8080}, \"mesh\":{ \"port\": 22860}, \"contract\": {\"roundtime\": 2000 }, \"log\":{\"loglevel\": \"inf\", \"loggers\":[\"console\",\"file\"]}}"
fi

vmpass=$(jq -r '.vmpass' $conf)
readarray -t vmaddrs <<< $(jq -r '.vms[]' $conf)
contdir=$basedir/$CONTRACT
vmcount=${#vmaddrs[@]}
mode=$1
hpcore=$(realpath ../..)

# Check if second arg (nodeid) is a number or not.
# If it's a number then reduce 1 from it to get zero-based node index.
if ! [[ $2 =~ ^[0-9]+$ ]] ; then
    let nodeid=-1
else
    let nodeid=$2-1
fi

if [ "$mode" = "info" ] || [ "$mode" = "new" ] || [ "$mode" = "updatebin" ] || [ "$mode" = "updateconfig" ] || [ "$mode" = "reconfig" ] || \
   [ "$mode" = "start" ] || [ "$mode" = "stop" ] || [ "$mode" = "check" ] || [ "$mode" = "log" ] || [ "$mode" = "kill" ] || \
   [ "$mode" = "ssh" ] || [ "$mode" = "reboot" ] || [ "$mode" = "ssl" ] || [ "$mode" = "lcl" ] || [ "$mode" = "pubkey" ]; then
    echo "mode: $mode ($contdir)"
else
    echo "Invalid command. [ info | new | updatebin <N> | updateconfig <N> | reconfig" \
        " | start [N] | stop [N] | check [N] | log <N> | kill [N] | reboot <N> | ssh <N>or<command>" \
        " | ssl <email>or<N> <email> | lcl | pubkey <N> ] expected."
    exit 1
fi

# Command modes:
# info - Displays information about current cluster configuration status.
# new - Install hot pocket dependencies and hot pocket with example contracts to each vm.
# updatebin - Deploy updated hot pocket and example binaries into specified vm node or entire cluster.
# updateconfig - Updates the config file of specified vm node or entire cluster.
# reconfig - Cleans and reconfigures the entire cluster using already uploaded HP binaries.
# start - Run hot pocket on specified vm node or entire cluster.
# stop - Gracefully stop hot pocket (if running) on specified vm node or entire cluster.
# check - Get hot pocket running process ids on specified vm node or entire cluster.
# log - Stream hot pocket console output log (if running) on specified vm node.
# kill - Force kill hot pocket (if running) on specified vm node or entire cluster.
# reboot - Reboot specified vm node.
# ssh - Open up an ssh terminal for the specified vm node.
# ssl - Creates LetsEncrypt ssl certs matching with the vm domain name.
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
            # Interpret second arg as a command to execute on all nodes.
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

if [ $mode = "ssl" ]; then
    if [ $nodeid = -1 ]; then
        if [ -n "$2" ]; then
            # If nodeid is not specified, interpret second arg as the ssl account notification email.
            command="$contdir/ssl.sh $2"
            for (( i=0; i<$vmcount; i++ ))
            do
                vmaddr=${vmaddrs[i]}
                let nodeid=$i+1
                echo "node"$nodeid":" $(sshpass -p $vmpass ssh $vmuser@$vmaddr $command) &
            done
            wait
        else
            echo "Please specify node no. or ssl account notification email."
            exit 1
        fi
    else
        # if nodeid is specified, interpret third arg as the ssl account notification email.
        if [ -n "$3" ]; then
            command="$contdir/ssl.sh $3"
            vmaddr=${vmaddrs[$nodeid]}
            sshpass -p $vmpass ssh $vmuser@$vmaddr $command
        else
            echo "Please specify ssl account notification email."
            exit 1
        fi
    fi
    exit 0
fi

if [ $mode = "lcl" ]; then
    command="$contdir/lcl.sh"
    for (( i=0; i<$vmcount; i++ ))
    do
        vmaddr=${vmaddrs[i]}
        let nodeid=$i+1
        echo "node"$nodeid":" $(sshpass -p $vmpass ssh $vmuser@$vmaddr $command) &
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

# All code below this will only execute in 'new', 'updatebin' or 'reconfig' mode.
# Run setup/configuration of entire cluster.

# Copy required files to remote node hpfiles dir.

if [ $mode = "new" ] || [ $mode = "updatebin" ]; then
    mkdir -p hpfiles/{bin,ssl,nodejs_contract}
    strip $hpcore/build/hpcore
    strip $hpcore/build/appbill
    cp $hpcore/build/{hpcore,hpfs,hpws} hpfiles/bin/
    cp $hpcore/examples/nodejs_contract/{package.json,echo_contract.js,hp-contract-lib.js} \
        hpfiles/nodejs_contract/
fi

if [ $mode = "new" ]; then
    cp ../bin/{libfuse3.so.3,libblake3.so,fusermount3,hpws,hpfs} hpfiles/bin/
    cp ./setup-hp.sh hpfiles/
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ] || [ $mode = "updateconfig" ]; then
    mkdir ./cfg > /dev/null 2>&1
fi

# Running vm setup script on specified node or entire cluster.
if [ $nodeid = -1 ]; then
    for (( i=0; i<$vmcount; i++ ))
    do
        vmaddr=${vmaddrs[i]}
        let nodeid=$i+1
        # Setup vm. (This will download hp.cfg in 'new', 'reconfig', 'updateconfig' modes)
        /bin/bash ./setup-vm.sh $mode $nodeid $vmuser $vmpass $vmaddr $basedir $contdir &
    done
    wait
else
    vmaddr=${vmaddrs[$nodeid]}
    sshpass -p $vmpass ssh $vmuser@$vmaddr $command
    # Setup vm. (This will download hp.cfg in 'new' or 'reconfig' modes)
    /bin/bash ./setup-vm.sh $mode $nodeid $vmuser $vmpass $vmaddr $basedir $contdir
fi

rm -r hpfiles > /dev/null 2>&1

if [ $mode = "updatebin" ]; then
    exit 0
fi

# All code below this will only execute in 'new', 'reconfig' or 'updateconfig' mode.

# In 'new' and 'reconfig' modes, update downloaded hp.cfg files from all nodes to be part of the same UNL cluster.
# In 'updateconfig' mode, simply update the config of specified node or entire cluster.

if [ $mode = "new" ] || [ $mode = "reconfig" ]; then

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
    echo "Generating merged hp.cfg files..."
    for (( j=0; j<$vmcount; j++ ))
    do
        let n=$j+1

        # Prepare peer and unl lists (skip self node for peers).
        mypeers=$(joinarr peers $j)
        # Skip param is passed as -1 to stop skipping self pubkey.
        myunl=$(joinarr pubkeys -1)

        # Merge json contents to produce final config.
        echo "$(cat ./cfg/node$n.cfg)" \
            '{"contract": {"id": "3c349abe-4d70-4f50-9fa6-018f1f2530ab", "bin_path": "/usr/bin/node", "bin_args": "'$basedir'/hpfiles/nodejs_contract/echo_contract.js", "unl": '${myunl}'}}'\
            '{"mesh": {"known_peers": '${mypeers}'}}'\
            $contconfig \
            | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$n-merged.cfg
    done
    
elif [ $mode = "updateconfig" ]; then

    echo "Generating merged hp.cfg files..."
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$vmcount; i++ ))
        do
            vmaddr=${vmaddrs[i]}
            let nodeid=$i+1

            # Merge json contents to produce final config.
            echo "$(cat ./cfg/node$nodeid.cfg)" \
                $contconfig \
                | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$nodeid-merged.cfg
        done
    else
        # Merge json contents to produce final config.
        echo "$(cat ./cfg/node$nodeid.cfg)" \
            $contconfig \
            | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$nodeid-merged.cfg
    fi

fi

# Upload local hp.cfg files back to specified node or entire cluster.
if [ $nodeid = -1 ]; then
    for (( i=0; i<$vmcount; i++ ))
    do
        vmaddr=${vmaddrs[i]}
        let nodeid=$i+1

        echo "Uploading configured hp.cfg to node $nodeid..."
        sshpass -p $vmpass scp ./cfg/node$nodeid-merged.cfg $vmuser@$vmaddr:$contdir/cfg/hp.cfg &
    done
    wait
else
    echo "Uploading configured hp.cfg to node $nodeid..."
    sshpass -p $vmpass scp ./cfg/node$nodeid-merged.cfg $vmuser@$vmaddr:$contdir/cfg/hp.cfg
fi

rm -r ./cfg
echo "Done."
