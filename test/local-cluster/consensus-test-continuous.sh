#!/bin/bash
#Script from Richard Holland

WINDOWSIZE=60 # size of window in seconds to examine for successful consensus rounds
PIPE=concon.pipe
clusterloc=$(pwd)/hpcluster
n=1
hpversion=0.6.4
let pubport=8080+$n
while true; do
    
    stat $PIPE 2>/dev/null >/dev/null
    PIPEEXISTS=$?
    if [ ! "$PIPEEXISTS" -eq "0" ]; then
        mkfifo $PIPE
    else
        dd if=$PIPE iflag=nonblock of=/dev/null 2> /dev/null > /dev/null
    fi

    exec 9<>$PIPE

    echo 'starting ...'
    STARTTIME=`date +%s`
    nohup docker run --rm -t --network=hpnet --name=node${n} \
        -p ${pubport}:${pubport} -a stderr -a stdout \
        --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
        --mount type=bind,source=${clusterloc}/node${n},target=/contract \
        hpcore:${hpversion} run /contract > $PIPE 2>> $PIPE 3>MARKER &
    PID=$!
    sleep 1

    EXISTINGCONTAINER=""
    kill -s 0 $PID 2> /dev/null 1> /dev/null
    if [ "$?" -gt "0" ];
    then
        echo 'exists, killing existing ...'

        while true; do
            read -t 0  line <&9
            if [ ! "$?" -eq "0" ]; then
                break;
            fi
            read -t 1 line <&9
            if [ "`echo $line | grep "already in use by container" | wc -l`" -gt "0" ]; then
                EXISTINGCONTAINER=`echo $line | grep -Eo 'container "[a-f0-9]+"' | cut -d '"' -f2`
                break
            fi
        done
        
        if [ ! -z "$EXISTINGCONTAINER" ]; then
            KPID=`ps aux | grep "$EXISTINGCONTAINER" | grep -v grep | awk '{print $2}'`
            if [ ! -z "$KPID" ]; then
                echo "killing $KPID"
                kill -9 $KPID
            fi
        fi
        continue
    else
        disown $PID
        echo "running"
    fi

    LASTROUND=0
    SUCCESSFULCLOSES=0
    while true
    do
        if read -t 1 line <&9; then
            TSRAW="`echo $line | cut -d" " -f1,2`"
            TS=`date --date="$TSRAW" +"%s" 2> /dev/null`
            if [ "$?" -gt " 0" ]; then
                ISFUSE=`echo $line | grep hpstatefs | wc -l`
                if [ "$ISFUSE" -gt "0" ]; then
                    continue
                fi
                echo "Irregular line: $line"
                continue
            fi
            if [ "$LASTROUND" -eq "0" ]; then
                LASTROUND=$TS
            fi
            
            SUCCESS="`echo $line | grep '****Ledger created****' | wc -l`"
            SUCCESSFULCLOSES="`echo $SUCCESSFULCLOSES + $SUCCESS | bc`"

            SHOULDPRINT=`echo "$TS - $LASTROUND > $WINDOWSIZE" | bc`

            if [ "$SHOULDPRINT" -gt "0" ];
            then
                echo "Window ending $TSRAW contained $SUCCESSFULCLOSES successful consensus rounds"
                SUCCESSFULCLOSES=0
                LASTROUND=$TS
            fi
        fi

        kill -s 0 $PID > /dev/null 2> /dev/null
        if [ "$?" -gt "0" ]; then
            echo docker process went away, quitting
            exit
        fi
    done
done