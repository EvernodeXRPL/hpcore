#!/bin/bash

if [ -x "$(command -v node)" ]; then
   echo "NodeJs already installed."
else
   echo "Installing NodeJs..."
   sudo apt-get update
   sudo apt-get -y install curl
   curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -
   sudo apt-get install -y nodejs
fi

if [ -x "$(command -v fusermount3)" ]; then
   echo "FUSE already installed."
else
   echo "Installing FUSE and other shared libraries..."
   sudo apt-get -y install libgomp1
   sudo cp ./libfuse3.so.3 ./libb2.so.1 /usr/local/lib/
   sudo ldconfig
   sudo cp ./fusermount3 /usr/local/bin/
fi

sudo rm -r ~/contract > /dev/null 2>&1
./hpcore new ./contract
pushd ./contract/cfg > /dev/null 2>&1
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem \
      -subj "/C=AU/ST=ST/L=L/O=O/OU=OU/CN=localhost/emailAddress=hp@example" > /dev/null 2>&1
popd > /dev/null 2>&1
