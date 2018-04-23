#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="zsub1x.conf"
BINARY_FILE="/usr/local/bin/sub1x"
zSub1x_REPO="https://github.com/SuB1X-Coin/zSub1x.git"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof zsub1xd)" ]; then
  echo -e "${GREEN}\c"
  read -e -p "zSub1x is already on. Proceed adding a new one? [Y/N]" NEW_zSub1x
  echo -e "{NC}"
  clear
else
  NEW_zSub1x="new"
fi
}

function prepare_system() {

echo -e "Getting ready to install zSub1x Masternode."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils \
libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw pwgen
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Something went wrong :(:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw"
 exit 1
fi

clear
echo -e "Checking if you are using a cheap VPS."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(swapon -s)
if [[ "$PHYMEM" -lt "2" && -z "$SWAP" ]];
  then
    echo -e "${GREEN}Cheap server detected. No problem, creating 2G swap file.${NC}"
    dd if=/dev/zero of=/swapfile bs=1024 count=2M
    chmod 600 /swapfile
    mkswap /swapfile
    swapon -a /swapfile
else
  echo -e "${GREEN}Server performance good.${NC}"
fi
clear
}



function compile_cropcoin() {
  echo -e "Clone git repo and compile it. This may take some time. Press a key to continue."
  read -n 1 -s -r -p ""

  git clone $zSub1x_REPO $TMP_FOLDER
  cd $TMP_FOLDER/src
  mkdir obj/support
  mkdir obj/crypto
  make -f makefile.unix
  compile_error zsub1x
  cp -a zsub1x $BINARY_FILE
  clear
}

function enable_firewall() {
  echo -e "Installing and setting up firewall to allow incomning access on port ${GREEN}$SUB1XCOINPORT${NC}"
  ufw allow $SUB1XPORT/tcp comment "SUB1X MN port" >/dev/null
  ufw allow $[SUB1XCOINPORT+1]/tcp comment "SUB1X RPC port" >/dev/null
  ufw allow ssh >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
}

function systemd_SUB1X() {
  cat << EOF > /etc/systemd/system/$SUB1XUSER.service
[Unit]
Description=SUB1X service
After=network.target
[Service]
Type=forking
User=$SUB1XUSER
Group=$SUB1XUSER
WorkingDirectory=$SUB1XHOME
ExecStart=$BINARY_FILE -daemon
ExecStop=$BINARY_FILE stop
Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=10s
StartLimitInterval=120s
StartLimitBurst=5
  
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $SUB1XUSER.service
  systemctl enable $SUB1XUSER.service >/dev/null 2>&1

  if [[ -z $(pidof  zsub1xd) ]]; then
    echo -e "${RED} zSub1xd is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo "systemctl start $SUB1XUSER.service"
    echo "systemctl status $SUB1XUSER.service"
    echo "less /var/log/syslog"
    exit 1
  fi
}

function ask_port() {
DEFAULTSUB1XPORT=5721
read -p "SUB1X Port: " -i $DEFAULTSUB1XPORT -e SUB1XPORT
: ${SUB1XPORT:=$DEFAULTSUB1XPORT}
}

function ask_user() {
  DEFAULTCROPCOINUSER="zsub1x"
  read -p "zSub1x user: " -i $DEFAULTSUB1XUSER -e SUB1XUSER
  : ${SUB1XUSER:=$DEFAULTSUB1XUSER}

  if [ -z "$(getent passwd $SUB1XUSER)" ]; then
    useradd -m $SUB1XUSER
    USERPASS=$(pwgen -s 12 1)
    echo "$SUB1XUSER:$USERPASS" | chpasswd

   SUB1XHOME=$(sudo -H -u $SUB1XUSER bash -c 'echo $HOME')
    DEFAULTSUB1XFOLDER="$SUB1XHOME/.zsub1x"
    read -p "Configuration folder: " -i $DEFAULTSUB1XFOLDER -e SUB1XFOLDER
    : ${SUB1XFOLDER:=$DEFAULTSUB1XFOLDER}
    mkdir -p $SUB1XFOLDER
    chown -R $SUB1XUSER: $SUB1XFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $SUB1XPORT ]] || [[ ${PORTS[@]} =~ $[SUB1XPORT+1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w10 | head -n1)
  RPCPASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w22 | head -n1)
  cat << EOF > $SUB1XFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[SUB1XPORT+1]
listen=1
server=1
daemon=1
port=$SUB1XPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e SUB1XKEY
  if [[ -z "$SUB1XKEY" ]]; then
  sudo -u $SUB1XUSER /usr/local/bin/zsub1xd -conf=$SUB1XFOLDER/$CONFIG_FILE -datadir=$SUB1XFOLDER
  sleep 5
  if [ -z "$(pidof zsub1xd)" ]; then
   echo -e "${RED}Zsub1x server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
  SUB1XKEY=$(sudo -u $SUB1XUSER $BINARY_FILE -conf=$SUB1XFOLDER/$CONFIG_FILE -datadir=$SUB1XFOLDER masternode genkey)
  sudo -u $SUB1XUSER $BINARY_FILE -conf=$SUB1XFOLDER/$CONFIG_FILE -datadir=$SUB1XFOLDER stop
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $SUB1XFOLDER/$CONFIG_FILE
  NODEIP=$(curl -s4 icanhazip.com)
  cat << EOF >> $SUB1XFOLDER/$CONFIG_FILE
logtimestamps=1
maxconnections=256
masternode=1
masternodeaddr=$NODEIP:$SUB1XPORT
masternodeprivkey=$SUB1XKEY
EOF
  chown -R $SUB1XUSER: $SUB1XFOLDER >/dev/null
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "Cropcoin Masternode is up and running as user ${GREEN}$SUB1XUSER${NC} and it is listening on port ${GREEN}$SUB1XPORT${NC}."
 echo -e "${GREEN}$SUB1XUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$SUB1XFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $SUB1XUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $SUB1XUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$SUB1XPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$SUB1XKEY${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  systemd_cropcoin
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_SUB1X" == "y" || "$NEW_SUB1X" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_SUB1X" == "new" ]]; then
  prepare_system
  ask_permission
  if [[ "$MYR3L" == "YES" ]]; then
    deploy_binaries
  else
    compile_zsub1x
  fi
  setup_node
else
  echo -e "${GREEN}zSub1x already running.${NC}"
  exit 0
fi
