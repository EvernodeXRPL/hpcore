#!/bin/bash

if [ -x "$(command -v node)" ]; then
   echo "NodeJs is installed."
else
   echo "Installing NodeJs..."
   sudo apt-get update
   sudo apt-get -y install curl
   curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -
   sudo apt-get install -y nodejs

   # FUSE
   sudo cp ./libfuse3.so.3 /usr/local/lib/
   sudo ldconfig
   # Install fuse.
   sudo apt-get update && apt-get install -y fuse && rm -rf /var/lib/apt/lists/*
fi

if [ ! -d "./contract" ]; then
   ./hpcore new ./contract
   pushd ./contract/cfg
   openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem \
         -subj "/C=AU/ST=ST/L=L/O=O/OU=OU/CN=localhost/emailAddress=hp@example" > /dev/null 2>&1
   popd
fi

