#!/bin/bash
# Hot Pocket - create release package

if [ -z "$1" ]
then
      echo "Release Version not specified."
      exit 1
fi

RELVERSION="hp-${1}"
RELEASEDIR=./release/$RELVERSION

cmake . -DCMAKE_BUILD_TYPE=Release
make

rm -rf ./release

# Copy hpcore binary
mkdir -p $RELEASEDIR
cp build/hpcore $RELEASEDIR/hpcore
$RELEASEDIR/hpcore new $RELEASEDIR/echocontract

# Copy example client
mkdir $RELEASEDIR/hpclient
cp -r examples/hpclient/client.js $RELEASEDIR/hpclient
cp -r examples/hpclient/package.json $RELEASEDIR/hpclient
echo "npm install hpclient"
npm --prefix $RELEASEDIR/hpclient install > /dev/null 2>&1

# Copy example contract
CTRPATH=./bin/contract.js
CFGPATH=${RELEASEDIR}/echocontract/cfg/hp.cfg
CFGJSON=${RELEASEDIR}/echocontract/cfg/hp.json
mv $CFGPATH $CFGJSON
node -p "JSON.stringify({...require('${CFGJSON}'), binary:'/usr/bin/node', binargs:'${CTRPATH}' }, null, 2)" > $CFGPATH
rm $CFGJSON
mkdir -p $RELEASEDIR/echocontract/bin
cp -r examples/echocontract/contract.js $RELEASEDIR/echocontract/bin
cp -r examples/echocontract/package.json $RELEASEDIR/echocontract/bin
echo "npm install echocontract"
npm --prefix $RELEASEDIR/echocontract/bin install > /dev/null 2>&1

echo "Creating tarball"
tar -C ./release -czf ./release/$RELVERSION.tar.gz $RELVERSION
rm -r $RELEASEDIR

echo "Release tarball has been created at ./release/${RELVERSION}.tar.gz"

# Switch cmake back to Debug build mode
cmake . -DCMAKE_BUILD_TYPE=Debug
exit 0