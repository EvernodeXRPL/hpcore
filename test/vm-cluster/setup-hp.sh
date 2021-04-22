#!/bin/bash

mode=$1
basedir=$2
contdir=$3 # Contract directory
vmaddr=$4

if [[ ! -f /swapfile ]]
then
   echo "Adding 5GB swap space..."
   sudo fallocate -l 5G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile  
fi

# Getting updates if any
echo "Checking for updates..."
sudo apt-get update

if [ -x "$(command -v node)" ]; then
   echo "NodeJs already installed."
else
   echo "Installing NodeJs..."
   sudo apt-get update
   sudo apt-get -y install curl
   curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
   sudo apt-get install -y nodejs
fi

if [ -x "$(command -v fusermount3)" ]; then
   echo "FUSE already installed."
else
   echo "Installing FUSE and other shared libraries..."
   sudo apt-get -y install libgomp1 libssl-dev
   sudo cp $basedir/hpfiles/bin/{libfuse3.so.3,libblake3.so} /usr/local/lib/
   sudo ldconfig
   sudo cp $basedir/hpfiles/bin/fusermount3 /usr/local/bin/
fi

if [ -x "$(command -v sqlite3)" ]; then
   echo "SQLite already installed."
else
   echo "Installing SQLite..."
   sudo apt-get install -y sqlite3 libsqlite3-dev
fi


# Remove existing contract dir.
sudo rm -r $contdir > /dev/null 2>&1

echo "Creating new contract directory..."
$basedir/hpfiles/bin/hpcore new $contdir

if [ -f $basedir/hpfiles/ssl/tlscert.pem ]; then
   echo "Copying ssl certs to contract directory..."
   cp -rf $basedir/hpfiles/ssl/* $contdir/cfg/
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
   echo "echo hpcore pid:\$($contdir/getpid.sh hpcore)  hpfs pid:\$($contdir/getpid.sh hpfs)  hpws pid:\$($contdir/getpid.sh hpws)" > $contdir/check.sh
   sudo chmod +x $contdir/check.sh

   # Create kill.sh script
   echo "sudo kill \$($contdir/getpid.sh hpcore hpfs hpws)" > $contdir/kill.sh
   sudo chmod +x $contdir/kill.sh

   # Create lcl.sh script
   echo "max_shard_no=\$(ls -v $contdir/ledger_fs/seed/primary/ | tail -2 | head -1)" > $contdir/lcl.sh
   echo "echo \"select seq_no || '-' || lower(hex(ledger_hash)) from ledger order by seq_no DESC limit 1;\" | sqlite3 file:$contdir/ledger_fs/seed/primary/\$max_shard_no/ledger.sqlite?mode=ro" >> $contdir/lcl.sh
   sudo chmod +x $contdir/lcl.sh

   # Create ssl.sh script
   # This installs LetsEncrypt certbot and generates the SSL certs maching to vm domain name.
   echo "snap install --classic certbot && ln -s /snap/bin/certbot /usr/bin/certbot" > $contdir/ssl.sh
   echo "certbot certonly --standalone -n -m $1 --agree-tos -d $vmaddr" > $contdir/ssl.sh
   echo "cp /etc/letsencrypt/live/$vmaddr/fullchain.pem $contdir/cfg/tlscert.pem" > $contdir/ssl.sh
   echo "cp /etc/letsencrypt/live/$vmaddr/privkey.pem $contdir/cfg/tlskey.pem" > $contdir/ssl.sh

   # Configure .screenrc
   pushd $contdir > /dev/null 2>&1
   echo "chdir $contdir" >> hp.screenrc
   echo "sessionname hp_$(basename $contdir)" >> hp.screenrc
   echo "bindkey \"^C\" echo 'Blocked. Ctrl+A,D to detach.'" >> hp.screenrc
   popd > /dev/null 2>&1
fi
