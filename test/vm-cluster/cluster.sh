#!/bin/bash
# Hot Pocket cluster management script.

# Usage examples:
# ./cluster.sh new
# ./cluster.sh updatebin
# ./cluster.sh start 1
# ./cluster.sh start

# Command modes:
# info - Displays information about current cluster configuration status.
# select - Sets the currently active contract from the list of contracts defined in cluster config file.
# new - Install hot pocket dependencies and hot pocket with example contracts to each node.
# updatebin - Deploy updated hot pocket and example binaries into specified node or entire cluster.
# updateconfig - Updates the config file of specified node or entire cluster.
# reconfig - Cleans and reconfigures the entire cluster using already uploaded HP binaries.
# start - Run hot pocket on specified node or entire cluster.
# stop - Gracefully stop hot pocket (if running) on specified node or entire cluster.
# check - Get hot pocket running process ids on specified node or entire cluster.
# log - Stream hot pocket console output log (if running) on specified node.
# kill - Force kill hot pocket (if running) on specified node or entire cluster.
# reboot - Reboot specified node.
# ssh - Open up an ssh terminal for the specified node.
# ssl - Creates LetsEncrypt ssl certs matching with the domain name.
# lcl - Displays the lcls of all nodes.
# pubkey - Displays the pubkey on specified node or entire cluster.

mode=$1
hpcore=$(realpath ../..)

if [ "$mode" = "info" ] || [ "$mode" = "select" ] ||
   [ "$mode" = "new" ] || [ "$mode" = "updatebin" ] || [ "$mode" = "updateconfig" ] || [ "$mode" = "reconfig" ] || \
   [ "$mode" = "start" ] || [ "$mode" = "stop" ] || [ "$mode" = "check" ] || [ "$mode" = "log" ] || [ "$mode" = "kill" ] || \
   [ "$mode" = "ssh" ] || [ "$mode" = "reboot" ] || [ "$mode" = "ssl" ] || [ "$mode" = "lcl" ] || [ "$mode" = "pubkey" ]; then
    echo "mode: $mode"
else
    echo "Invalid command."
    echo " Expected: info | select | new | updatebin <N> | updateconfig [N] | reconfig" \
        " | start [N] | stop [N] | check [N] | log <N> | kill [N] | reboot <N> | ssh <N>or<command>" \
        " | ssl <email>or<N> <email> | lcl | pubkey [N]"
    echo " <N>: Required node no.   [N]: Optional node no."
    exit 1
fi

# jq command is used for json manipulation.
if ! command -v jq &> /dev/null
then
    sudo apt-get install -y jq
fi

configfile=config.json
if [ ! -f $configfile ]; then
    # Create default config file.
    echo '{"selected":"contract","contracts":[{"name":"contract","sshuser":"root","sshpass":"","hosts":[],"config":{}}]}' | jq . > $configfile
fi

if [ $mode = "select" ]; then
    selectedcont=$2
    if [ "$selectedcont" = "" ]; then
        echo "Please specify contract name to select."
        exit 1
    fi
    continfo=$(jq -r ".contracts[] | select(.name == \"$selectedcont\")" $configfile)
    if [ "$continfo" = "" ]; then
        echo "No configuration found for selected contract '"$selectedcont"'"
        exit 1
    fi

    # Set the 'selected' field value on cluster config file.
    jq ".selected = \"$selectedcont\"" $configfile > $configfile.tmp && mv $configfile.tmp $configfile
    echo "Selected '"$selectedcont"'"
    exit 0
fi

selectedcont=$(jq -r '.selected' $configfile)
if [ "$selectedcont" = "" ]; then
    echo "No contract selected."
    exit 1
fi

continfo=$(jq -r ".contracts[] | select(.name == \"$selectedcont\")" $configfile)
if [ "$continfo" = "" ]; then
    echo "No configuration found for selected contract '"$selectedcont"'"
    exit 1
fi

# Read ssh user and password and set contract directory based on username.
sshuser=$(echo $continfo | jq -r '.sshuser')
sshpass=$(echo $continfo | jq -r '.sshpass')
if [ "$sshuser" = "" ]; then
    echo "sshuser not specified."
    exit 1
elif [ "$sshuser" = "root" ]; then
    basedir=/$sshuser
else
    basedir=/home/$sshuser
fi
contdir=$basedir/$selectedcont
hpfiles="hpfiles/"$selectedcont

# Call vultr rest api GET. (params: endpoint, vultrapikey)
function vultrget() {
    local _result=$(curl --silent "https://api.vultr.com/v2/$1" -X GET -H "Authorization: Bearer $2" -H "Content-Type: application/json" -w "\n%{http_code}")
    local _parts
    readarray -t _parts < <(printf '%s' "$_result") # break parts by new line.
    if [[ ${_parts[1]} == 2* ]]; then # Check for 2xx status code.
        [ ! -z "${_parts[0]}" ] && echo ${_parts[0]} # Return api output if there is any.
    else
        >&2 echo "Error on vultrget code:${_parts[1]} body:${_parts[0]}" && exit 1
    fi
}

# Read the hosts list.
readarray -t hostaddrs < <(printf '%s' "$(echo $continfo | jq -r '.hosts[]')")
# Check whether the first host is "vultr:<group_name>". If so read ips from vultr.
readarray -d ":" -t _host1parts < <(printf '%s' "${hostaddrs[0]}")
if [[ ${_host1parts[0]} == "vultr" ]]; then
    _vultrapikey=$(jq -r ".vultr.api_key" $configfile)
    [ -z $_vultrapikey ] && >&2 echo "Vultr api key not found." && exit 1
    _vultrvms=$(vultrget "instances?tag=${_host1parts[1]}" "$_vultrapikey")
    [ -z "$_vultrvms" ] && exit 1
    _vultrips=$(echo $(echo $_vultrvms | jq -r ".instances | sort_by(.label) | .[] | .main_ip"))
    readarray -d " " -t hostaddrs < <(printf '%s' "$_vultrips") # Populate hostaddrs with ips retrieved from vultr.
    echo "Retrieved ${#hostaddrs[@]} host addresses from vultr."
fi
hostcount=${#hostaddrs[@]}

# Read the contract config which should be applied to hp.cfg.
contconfig=$(echo $continfo | jq -r '.config')
if [ "$contconfig" = "" ] || [ "$contconfig" = "{}" ]; then
    # Apply default config.
    contconfig="{\"user\": {\"port\": 8080}, \"mesh\":{ \"port\": 22860}, \"contract\": {\"roundtime\": 2000 }, \"log\":{\"loglevel\": \"inf\", \"loggers\":[\"console\",\"file\"]}}"
fi

# Check if second arg (nodeid) is a number or not.
# If it's a number then reduce 1 from it to get zero-based node index.
if ! [[ $2 =~ ^[0-9]+$ ]] ; then
    let nodeid=-1
else
    let nodeid=$2-1
fi

echo " dir: "$contdir

if [ $mode = "info" ]; then
    for (( i=0; i<$hostcount; i++ ))
    do
        let n=$i+1
        hostaddr=${hostaddrs[i]}
        echo "node"$n": "$hostaddr
    done
    echo $contconfig
    exit 0
fi

if [ $mode = "start" ]; then
    # Use the screen command so that the execution does not stop when ssh session ends.
    command="mkdir -p $contdir/screen && screen -c $contdir/hp.screenrc -m -d bash $contdir/start.sh"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            sshpass -p $sshpass ssh $sshuser@$hostaddr $command &
        done
        wait
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh $sshuser@$hostaddr $command
    fi
    exit 0
fi

if [ $mode = "stop" ]; then
    command="$contdir/stop.sh"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            sshpass -p $sshpass ssh $sshuser@$hostaddr $command &
        done
        wait
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh $sshuser@$hostaddr $command
    fi
    exit 0
fi

if [ $mode = "check" ]; then
    command="$contdir/check.sh"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            let n=$i+1
            echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
        done
        wait
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh $sshuser@$hostaddr $command
    fi
    exit 0
fi

if [ $mode = "log" ]; then
    if [ $nodeid = -1 ]; then
        echo "Please specify node no.."
        exit 1
    fi
    hostaddr=${hostaddrs[$nodeid]}
    sshpass -p $sshpass ssh -t $sshuser@$hostaddr screen -r -S hp_$(basename $contdir)
    exit 0
fi

if [ $mode = "kill" ]; then
    command="$contdir/kill.sh"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            let n=$i+1
            echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
        done
        wait
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh $sshuser@$hostaddr $command
    fi
    exit 0
fi

if [ $mode = "reboot" ]; then
    if [ $nodeid = -1 ]; then
        echo "Please specify node no."
        exit 1
    fi
    hostaddr=${hostaddrs[$nodeid]}
    sshpass -p $sshpass ssh $sshuser@$hostaddr 'sudo reboot'
    exit 0
fi

if [ $mode = "ssh" ]; then
    if [ $nodeid = -1 ]; then
        if [ -n "$2" ]; then
            # Interpret second arg as a command to execute on all nodes.
            command=${*:2}
            echo "Executing '$command' on all nodes..."
            for (( i=0; i<$hostcount; i++ ))
            do
                hostaddr=${hostaddrs[i]}
                let n=$i+1
                echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
            done
            wait
            exit 0
        else
            echo "Please specify node no. or command to execute on all nodes."
            exit 1
        fi
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh -t $sshuser@$hostaddr "cd $contdir ; bash"
        exit 0
    fi
fi

if [ $mode = "ssl" ]; then
    if [ $nodeid = -1 ]; then
        if [ -n "$2" ]; then
            # If nodeid is not specified, interpret second arg as the ssl account notification email.
            command="$contdir/ssl.sh $2"
            for (( i=0; i<$hostcount; i++ ))
            do
                hostaddr=${hostaddrs[i]}
                let n=$i+1
                echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
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
            hostaddr=${hostaddrs[$nodeid]}
            sshpass -p $sshpass ssh $sshuser@$hostaddr $command
        else
            echo "Please specify ssl account notification email."
            exit 1
        fi
    fi
    exit 0
fi

if [ $mode = "lcl" ]; then
    command="$contdir/lcl.sh"
    for (( i=0; i<$hostcount; i++ ))
    do
        hostaddr=${hostaddrs[i]}
        let n=$i+1
        echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
    done
    wait
    exit 0
fi

if [ $mode = "pubkey" ]; then
    command="cat $contdir/cfg/hp.cfg | grep public_key | cut -d '\"' -f4"
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            let n=$i+1
            echo "node"$n":" $(sshpass -p $sshpass ssh $sshuser@$hostaddr $command) &
        done
        wait
    else
        hostaddr=${hostaddrs[$nodeid]}
        sshpass -p $sshpass ssh $sshuser@$hostaddr $command
    fi
    exit 0
fi

# All code below this will only execute in 'new', 'updatebin' or 'reconfig' mode.
# Run setup/configuration of entire cluster.

# Copy required files to remote node hpfiles dir.

if [ $mode = "new" ] || [ $mode = "updatebin" ]; then
    rm -r hpfiles > /dev/null 2>&1
    mkdir -p $hpfiles/{bin,ssl,nodejs_contract}
    strip $hpcore/build/hpcore
    strip $hpcore/build/appbill
    cp $hpcore/build/{hpcore,hpfs,hpws} $hpfiles/bin/
    cp $hpcore/examples/nodejs_contract/{package.json,echo_contract.js,hp-contract-lib.js} \
        $hpfiles/nodejs_contract/
fi

if [ $mode = "new" ]; then
    cp ../bin/{libfuse3.so.3,libblake3.so,fusermount3,hpws,hpfs} $hpfiles/bin/
    cp ./setup-hp.sh $hpfiles/
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ] || [ $mode = "updateconfig" ]; then
    mkdir ./cfg > /dev/null 2>&1
fi

# Running node setup script on specified node or entire cluster.
if [ $nodeid = -1 ]; then
    for (( i=0; i<$hostcount; i++ ))
    do
        hostaddr=${hostaddrs[i]}
        let n=$i+1
        # Setup node. (This will download hp.cfg in 'new', 'reconfig', 'updateconfig' modes)
        /bin/bash ./setup-node.sh $mode $n $sshuser $sshpass $hostaddr $basedir $contdir $hpfiles &
    done
    wait
else
    hostaddr=${hostaddrs[$nodeid]}
    let n=$nodeid+1
    # Setup node. (This will download hp.cfg in 'new', 'reconfig', 'updateconfig' modes)
    /bin/bash ./setup-node.sh $mode $n $sshuser $sshpass $hostaddr $basedir $contdir $hpfiles
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
    for (( i=0; i<$hostcount; i++ ))
    do
        hostaddr=${hostaddrs[i]}
        let n=$i+1

        # Collect each node's pub key and peer address.
        pubkeys[i]=$(jq -r ".node.public_key" ./cfg/node$n.cfg)
        peers[i]="$hostaddr:$peerport"
    done

    # Function to generate JSON array string while skiping a given index.
    function joinarr {
        arrname=$1[@]
        arr=("${!arrname}")
        skip=$2

        let prevlast=$hostcount-2
        # Resetting prevlast if nothing is given to skip.
        if [ $skip -lt 0 ]
        then
            let prevlast=prevlast+1
        fi

        j=0
        str="["
        for (( i=0; i<$hostcount; i++ ))
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
    for (( j=0; j<$hostcount; j++ ))
    do
        let n=$j+1

        # Prepare peer and unl lists (skip self node for peers).
        mypeers=$(joinarr peers $j)
        # Skip param is passed as -1 to stop skipping self pubkey.
        myunl=$(joinarr pubkeys -1)

        # Merge json contents to produce final config.
        echo "$(cat ./cfg/node$n.cfg)" \
            '{"contract": {"id": "3c349abe-4d70-4f50-9fa6-018f1f2530ab", "bin_path": "/usr/bin/node", "bin_args": "'$basedir'/'$hpfiles'/nodejs_contract/echo_contract.js", "unl": '${myunl}'}}'\
            '{"mesh": {"known_peers": '${mypeers}'}}'\
            $contconfig \
            | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$n-merged.cfg
    done
    
elif [ $mode = "updateconfig" ]; then

    echo "Generating merged hp.cfg files..."
    if [ $nodeid = -1 ]; then
        for (( i=0; i<$hostcount; i++ ))
        do
            hostaddr=${hostaddrs[i]}
            let n=$i+1

            # Merge json contents to produce final config.
            echo "$(cat ./cfg/node$n.cfg)" \
                $contconfig \
                | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$n-merged.cfg
        done
    else
        # Merge json contents to produce final config.
        let n=$nodeid+1
        echo "$(cat ./cfg/node$n.cfg)" \
            $contconfig \
            | jq --slurp 'reduce .[] as $item ({}; . * $item)' > ./cfg/node$n-merged.cfg
    fi

fi

# Upload local hp.cfg files back to specified node or entire cluster.
echo "Uploading configured hp.cfg..."
if [ $nodeid = -1 ]; then
    for (( i=0; i<$hostcount; i++ ))
    do
        hostaddr=${hostaddrs[i]}
        let n=$i+1

        sshpass -p $sshpass scp ./cfg/node$n-merged.cfg $sshuser@$hostaddr:$contdir/cfg/hp.cfg &
    done
    wait
else
    let n=$nodeid+1
    sshpass -p $sshpass scp ./cfg/node$n-merged.cfg $sshuser@$hostaddr:$contdir/cfg/hp.cfg
fi

rm -r ./cfg
echo "Done."
