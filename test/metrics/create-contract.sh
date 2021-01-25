#!/bin/bash

vmaddr=45.32.115.63
vmuser=root
vmpass=hpgeveo123

scriptpath=$(dirname $(realpath $0))
bindir=$(realpath $scriptpath/../../build)
hpcore=$bindir/hpcore
contractdir=$scriptpath/metric-contract

rm -r $contractdir 2>/dev/null
$hpcore new $contractdir
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout $contractdir/cfg/tlskey.pem -out $contractdir/cfg/tlscert.pem -subj "/C=AU/ST=ACT/L=AU/O=hpws/CN=hpws"
# This assumes target vm hp binaries to be in ~/hpfiles/bin/
echo "~/hpfiles/bin/hpcore run ~/metric-contract" > $contractdir/run.sh
chmod +x $contractdir/run.sh

cp $scriptpath/{contract.js,hp-contract-lib.js} $contractdir/hpfs/seed/state/

# Merge json contents to produce final config.
echo "$(cat $contractdir/cfg/hp.cfg)" \
    '{"contract": {"id": "5657a933-74e3-4e5a-b1ab-c4de52a86cb3", "bin_path": "/usr/bin/node", "bin_args": "contract.js"}}'\
    | jq --slurp 'reduce .[] as $item ({}; . * $item)' > $contractdir/cfg/hp-merged.cfg
mv $contractdir/cfg/hp-merged.cfg $contractdir/cfg/hp.cfg

sshpass -p $vmpass scp -r $contractdir $vmuser@$vmaddr:~/

rm -r $contractdir