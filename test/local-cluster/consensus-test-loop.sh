#!/bin/bash
#Script from Richard Holland

clusterloc=$(pwd)/hpcluster
n=1
hpversion=0.6.0
let pubport=8080+$n
while true; do
    CONSENSUS="0"
    STARTTIME=`date +%s`
    nohup docker run --rm -t --network=hpnet --name=node${n} \
        -p ${pubport}:${pubport} -a stderr -a stdout \
        --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
        --mount type=bind,source=${clusterloc}/node${n},target=/contract \
        hpcore:${hpversion} run /contract  > contest.out 2>> contest.out &
    PID=$!
    sleep 1
    kill -s 0 $PID 2> /dev/null 1> /dev/null
    if [ "$?" -gt "0" ];
    then
        CONTAINERID=`cat contest.out | grep -Eo 'container "[a-f0-9]+"' | cut -d '"' -f2`
        if [ ! -z "$CONTAINERID" ]; then
            KPID=`ps aux | grep "$CONTAINERID " | grep -v grep | awk '{print $2}'`
            if [ ! -z "$KPID" ]; then
                kill -9 $KPID 
                continue
            fi
        fi
    else
        disown $PID
    fi
    echo "Started waiting for consensus on $PID at $STARTTIME"
    kill -s 0 $PID 2> /dev/null 1> /dev/null
    while [ "$?" -eq "0" ]; 
    do
        if [ "`cat contest.out | grep '****Ledger created****' | wc -l`" -gt "0" ];
        then
            break
        fi
        sleep 1
        UPTOTIME=`date +%s`
        TIMEELAPSED=`echo $UPTOTIME - $STARTTIME | bc `
        SHOULDPRINT=`echo $TIMEELAPSED % 10 | bc`
        if [ "$SHOULDPRINT" -eq "0" ]; then 
            echo "Still waiting after $TIMEELAPSED"
        fi
        kill -s 0 $PID 2> /dev/null 1> /dev/null
    done
    ENDTIME=`date +%s`
    TIMEELAPSED=`echo $ENDTIME - $STARTTIME | bc `
    echo "Reached consensus after $TIMEELAPSED seconds [PID=$PID], killing and restarting..."
    nohup kill -9 $PID 2> /dev/null 1> /dev/null
    sleep 1
done