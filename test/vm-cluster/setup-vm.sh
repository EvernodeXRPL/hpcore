#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmip=$4
hpcore=$5

echo $nodeid. $vmip

if [ $mode = "new" ]; then

    sshpass -p $vmpass scp $hpcore/build/hpcore \
                            $hpcore/build/hpstatemon \
                            $hpcore/examples/echocontract/contract.js \
                            $hpcore/examples/rndcontract/rnd_contract \
                            /usr/local/lib/x86_64-linux-gnu/libfuse3.so.3 \
                            /usr/local/bin/fusermount3 \
                            ./consensus-test-continuous.sh \
                            ./setup-hp.sh \
                            geveo@$vmip:~/

    sshpass -p $vmpass ssh geveo@$vmip 'chmod 700 ~/consensus-test-continuous.sh && chmod 700 ~/setup-hp.sh && ~/setup-hp.sh'
    sshpass -p $vmpass scp geveo@$vmip:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
else
    sshpass -p $vmpass scp $hpcore/build/hpcore \
                            $hpcore/build/hpstatemon \
                            $hpcore/examples/echocontract/contract.js \
                            $hpcore/examples/rndcontract/rnd_contract \
                            ./consensus-test-continuous.sh \
                            geveo@$vmip:~/
fi