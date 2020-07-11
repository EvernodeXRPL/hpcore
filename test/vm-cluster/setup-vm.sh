#!/bin/bash

mode=$1
nodeid=$2
vmpass=$3
vmip=$4
hpcore=$5

echo $nodeid. $vmip

strip $hpcore/build/hpcore

if [ $mode = "new" ]; then

    sshpass -f vmpass.txt scp $hpcore/build/hpcore \
                            $hpcore/examples/nodejs_contract/echo_contract.js \
                            ../bin/libfuse3.so.3 \
                            ../bin/libb2.so.1 \
                            ../bin/fusermount3 \
                            ../bin/websocketd \
                            ../bin/websocat \
                            ../bin/hpfs \
                            ./consensus-test-continuous.sh \
                            ./setup-hp.sh \
                            geveo@$vmip:~/

    sshpass -f vmpass.txt ssh geveo@$vmip 'chmod 700 ~/consensus-test-continuous.sh && chmod 700 ~/setup-hp.sh && ~/setup-hp.sh'
    sshpass -f vmpass.txt scp geveo@$vmip:~/contract/cfg/hp.cfg ./cfg/node$nodeid.json
else
    sshpass -f vmpass.txt scp $hpcore/build/hpcore \
                            $hpcore/examples/nodejs_contract/echo_contract.js \
                            ./consensus-test-continuous.sh \
                            geveo@$vmip:~/
fi