#!/bin/bash
#Script from Richard Holland

WINDOWSIZE=60 # size of window in seconds to examine for successful consensus rounds
PIPE=concon.pipe
clusterloc=$(pwd)/hpcluster
n=1
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
    nohup ~/hpcore run ~/contract > $PIPE 2>> $PIPE 3>MARKER &
    PID=$!
    sleep 1

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
            
            SUCCESS="`echo $line | grep '****Stage 3 consensus reached****' | wc -l`"
            SUCCESSFULCLOSES="`echo $SUCCESSFULCLOSES + $SUCCESS | bc`"

            SHOULDPRINT=`echo "$TS - $LASTROUND > $WINDOWSIZE" | bc`

            if [ "$SHOULDPRINT" -gt "0" ];
            then
                echo "Window ending $TSRAW contained $SUCCESSFULCLOSES successful consensus rounds"
                SUCCESSFULCLOSES=0
                LASTROUND=$TS
            fi
        fi

    done
done