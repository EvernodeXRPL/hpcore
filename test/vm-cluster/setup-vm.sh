#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmip=$4
hpcore=$5

echo $nodeid. $vmip

if [ $mode = "new" ]; then

    sshpass -f vmpass.txt scp $hpcore/build/hpcore \
                            $hpcore/build/hpstatemon \
                            $hpcore/examples/echo_contract/contract.js \
                            ../bin/libfuse3.so.3 \
                            ../bin/fusermount3 \
                            ../bin/websocketd \
                            ./consensus-test-continuous.sh \
                            ./setup-hp.sh \
                            geveo@$vmip:~/

    sshpass -f vmpass.txt ssh geveo@$vmip 'chmod 700 ~/consensus-test-continuous.sh && chmod 700 ~/setup-hp.sh && ~/setup-hp.sh'
    sshpass -f vmpass.txt scp geveo@$vmip:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
else
    sshpass -f vmpass.txt scp $hpcore/build/hpcore \
                            $hpcore/build/hpstatemon \
                            $hpcore/examples/echo_contract/contract.js \
                            ./consensus-test-continuous.sh \
                            geveo@$vmip:~/
fi