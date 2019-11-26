#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmip=$4
hpcore=$5

echo $nodeid. $vmip

sshpass -p $vmpass scp $hpcore/build/hpcore \
                        $hpcore/build/hpstatemon \
                        $hpcore/libfuse3.so.3 \
                        $hpcore/examples/echocontract/contract.js \
                        ./setup-hp.sh \
                        geveo@$vmip:~/


if [ $mode = "new" ]; then
    sshpass -p $vmpass ssh geveo@$vmip 'rm -r ~/contract && chmod 700 ~/setup-hp.sh && ~/setup-hp.sh'
else
    exit
fi

sshpass -p $vmpass scp geveo@$vmip:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json