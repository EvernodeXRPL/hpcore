#!/bin/bash

mode=$1
basedir=$2
contdir=$3 # Contract directory

if [[ ! -f /swapfile ]]
then
   echo "Adding 5GB swap space..."
   sudo fallocate -l 5G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile  
fi

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
   sudo cp $basedir/hpfiles/bin/{libfuse3.so.3,libblake3.so} /usr/local/lib/
   sudo ldconfig
   sudo cp $basedir/hpfiles/bin/fusermount3 /usr/local/bin/
fi

# Remove existing contract dir.
sudo rm -r $contdir > /dev/null 2>&1

echo "Creating new contract directory..."
$basedir/hpfiles/bin/hpcore new $contdir

if [ -f $basedir/hpfiles/ssl/tlscert.pem ]; then
   echo "Copying ssl certs to contract directory..."
   cp -rf $basedir/hpfiles/ssl/* $contdir/cfg/
else
   echo "Generating default ssl certs..."
   pushd $contdir/cfg > /dev/null 2>&1
   openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem \
         -subj "/C=AU/ST=ST/L=L/O=O/OU=OU/CN=localhost/emailAddress=hp@example" > /dev/null 2>&1
   popd > /dev/null 2>&1
fi

if [ $mode = "new" ] || [ $mode = "reconfig" ]; then
   # npm install to support nodejs contract
   pushd $basedir/hpfiles/nodejs_contract > /dev/null 2>&1
   npm install
   popd > /dev/null 2>&1

   # Create getpid script (gets process ids belonging to this contract dir)
   echo "ps -fp \$(pidof \$*) | grep $contdir | awk '{print \$2}' | tr '\n' ' '" > $contdir/getpid.sh
   sudo chmod +x $contdir/getpid.sh

   # Create start.sh script
   echo "$basedir/hpfiles/bin/hpcore run $contdir" > $contdir/start.sh
   sudo chmod +x $contdir/start.sh
   
   # Create stop.sh script (sending SIGINT to hpcore)
   echo "kill -2 \$($contdir/getpid.sh hpcore)" > $contdir/stop.sh
   sudo chmod +x $contdir/stop.sh

   # Create check.sh script (print pids belonging to this contract dir)
   echo "echo hpcore pid:\$($contdir/getpid.sh hpcore)  hpfs pid:\$($contdir/getpid.sh hpfs)  websocketd pid:\$($contdir/getpid.sh websocketd)  websocat pid:\$($contdir/getpid.sh websocat)" > $contdir/check.sh
   sudo chmod +x $contdir/check.sh

   # Create kill.sh script
   echo "sudo kill \$($contdir/getpid.sh hpcore hpfs websocketd websocat)" > $contdir/kill.sh
   sudo chmod +x $contdir/kill.sh

   # Configure .screenrc
   pushd $contdir > /dev/null 2>&1
   echo "chdir $contdir" >> hp.screenrc
   echo "sessionname hp_$(basename $contdir)" >> hp.screenrc
   echo "bindkey \"^C\" echo 'Blocked. Ctrl+A,D to detach.'" >> hp.screenrc
   popd > /dev/null 2>&1
fi
