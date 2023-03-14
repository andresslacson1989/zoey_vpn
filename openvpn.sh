#!/bin/bash
cp /usr/share/zoneinfo/Asia/Manila /etc/localtime
DOMAIN="https://zoey.bytesph.com"
IP=$(curl -s https://api.ipify.org)

install_require() {
    #send Updating
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Update&ip=$IP"
    clear
    echo "Updating System."
    {
        apt-get -o Acquire::ForceIPv4=true update
    } &>/dev/null
    clear
    echo "Preparing Installation"
    {
        apt-get -o Acquire::ForceIPv4=true install mysql-client -y
        apt-get -o Acquire::ForceIPv4=true install mariadb-server stunnel4 openvpn -y
        apt-get -o Acquire::ForceIPv4=true install dos2unix easy-rsa nano curl unzip jq virt-what net-tools -y
        apt-get -o Acquire::ForceIPv4=true install php-cli net-tools cron php-fpm php-json php-pdo php-zip php-gd php-mbstring php-curl php-xml php-bcmath php-json -y
        apt-get -o Acquire::ForceIPv4=true install gnutls-bin pwgen python -y
        apt-get -o Acquire::ForceIPv4=true install apache2 -y
        apt-get -o Acquire::ForceIPv4=true install php libapache2-mod-php php-mysql -y

    } \
        &>/dev/null
}

install_squid() {
    #send Squid
    curl -sb -X POST https://zoey.bytepsh.com/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Squid&ip=$IP"
    clear
    echo "Installing Proxy."
    {
        sudo touch /etc/apt/sources.list.d/trusty_sources.list
        echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | sudo tee --append /etc/apt/sources.list.d/trusty_sources.list >/dev/null
        sudo apt update -y

        sudo apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
        /bin/cat <<"EOM" >/etc/init.d/squid3
#! /bin/sh
#
# squid		Startup script for the SQUID HTTP proxy-cache.
#
# Version:	@(#)squid.rc  1.0  07-Jul-2006  luigi@debian.org
#
### BEGIN INIT INFO
# Provides:          squid
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Squid HTTP Proxy version 3.x
### END INIT INFO

NAME=squid3
DESC="Squid HTTP Proxy"
DAEMON=/usr/sbin/squid3
PIDFILE=/var/run/$NAME.pid
CONFIG=/etc/squid3/squid.conf
SQUID_ARGS="-YC -f $CONFIG"

[ ! -f /etc/default/squid ] || . /etc/default/squid

. /lib/lsb/init-functions

PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -x $DAEMON ] || exit 0

ulimit -n 65535

find_cache_dir () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']'$1'['"$w"']\+[^'"$w"']\+['"$w"']\+\([^'"$w"']\+\).$/\1/p;
			t end;
			d;
			:end q'`
        [ -n "$res" ] || res=$2
        echo "$res"
}

grepconf () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']'$1'['"$w"']\+\([^'"$w"']\+\).$/\1/p;
			t end;
			d;
			:end q'`
	[ -n "$res" ] || res=$2
	echo "$res"
}

create_run_dir () {
	run_dir=/var/run/squid3
	usr=`grepconf cache_effective_user proxy`
	grp=`grepconf cache_effective_group proxy`

	if [ "$(dpkg-statoverride --list $run_dir)" = "" ] &&
	   [ ! -e $run_dir ] ; then
		mkdir -p $run_dir
	  	chown $usr:$grp $run_dir
		[ -x /sbin/restorecon ] && restorecon $run_dir
	fi
}

start () {
	cache_dir=`find_cache_dir cache_dir`
	cache_type=`grepconf cache_dir`
	run_dir=/var/run/squid3

	#
	# Create run dir (needed for several workers on SMP)
	#
	create_run_dir

	#
	# Create spool dirs if they don't exist.
	#
	if test -d "$cache_dir" -a ! -d "$cache_dir/00"
	then
		log_warning_msg "Creating $DESC cache structure"
		$DAEMON -z -f $CONFIG
		[ -x /sbin/restorecon ] && restorecon -R $cache_dir
	fi

	umask 027
	ulimit -n 65535
	cd $run_dir
	start-stop-daemon --quiet --start \
		--pidfile $PIDFILE \
		--exec $DAEMON -- $SQUID_ARGS < /dev/null
	return $?
}

stop () {
	PID=`cat $PIDFILE 2>/dev/null`
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	#
	#	Now we have to wait until squid has really stopped.
	#
	sleep 2
	if test -n "$PID" && kill -0 $PID 2>/dev/null
	then
		log_action_begin_msg " Waiting"
		cnt=0
		while kill -0 $PID 2>/dev/null
		do
			cnt=`expr $cnt + 1`
			if [ $cnt -gt 24 ]
			then
				log_action_end_msg 1
				return 1
			fi
			sleep 5
			log_action_cont_msg ""
		done
		log_action_end_msg 0
		return 0
	else
		return 0
	fi
}

cfg_pidfile=`grepconf pid_filename`
if test "${cfg_pidfile:-none}" != "none" -a "$cfg_pidfile" != "$PIDFILE"
then
	log_warning_msg "squid.conf pid_filename overrides init script"
	PIDFILE="$cfg_pidfile"
fi

case "$1" in
    start)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Starting $DESC" "$NAME"
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	if stop ; then
		log_end_msg $?
	else
		log_end_msg $?
	fi
	;;
    reload|force-reload)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_action_msg "Reloading $DESC configuration files"
	  	start-stop-daemon --stop --signal 1 \
			--pidfile $PIDFILE --quiet --exec $DAEMON
		log_action_end_msg 0
	fi
	;;
    restart)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Restarting $DESC" "$NAME"
		stop
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    status)
	status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit 3
	;;
    *)
	echo "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|status}"
	exit 3
	;;
esac

exit 0
EOM

        sudo chmod +x /etc/init.d/squid3
        sudo update-rc.d squid3 defaults

        echo "acl SSH dst $IP
acl SSL_ports port 443
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
http_access deny manager
http_access deny all
http_port 8080
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname BytesPH-Proxy
error_directory /usr/share/squid3/errors/English" | sudo tee /etc/squid3/squid.conf
        sudo service squid3 restart
    } &>/dev/null
}

install_uptime() {
    {
        touch /var/www/html/uptime.php
        echo "<?php echo exec('uptime');" > /var/www/html/uptime.php

    }
}

install_openvpn() {

    #send OpenVPN
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=OpenVPN&ip=$IP"
    clear
    echo "Installing openvpn."
    {
        mkdir -p /etc/openvpn/easy-rsa/keys
        mkdir -p /etc/openvpn/login
        mkdir -p /etc/openvpn/server
        mkdir -p /var/www/html/stat
        touch /etc/openvpn/server.conf
        touch /etc/openvpn/server2.conf

        echo 'DNS=1.1.1.1
DNSStubListener=no' >>/etc/systemd/resolved.conf
        sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

        echo '# BytesPH OpenVPN Configuration
dev tun
port 53
proto udp
topology subnet
server 10.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher AES-128-GCM
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
comp-lzo
username-as-common-name
verify-client-cert none
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_udp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env #
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/udpserver.log
status /var/www/html/udpclient.log
verb 3' >/etc/openvpn/server.conf

        echo '# BytesPH OpenVPN Configuration
dev tun
port 110
proto tcp
topology subnet
server 10.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher AES-128-GCM
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
comp-lzo
username-as-common-name
verify-client-cert none
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env #
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/tcpserver.log
status /var/www/html/tcpclient.log
verb 3' >/etc/openvpn/server2.conf

        /bin/cat <<"EOM" >/etc/openvpn/login/auth_vpn
#!/bin/bash
##Authentication
data=$(curl -sb -X POST https://zoey.bytepsh.com/api/server/login -H "Content-Type: application/x-www-form-urlencoded" -d "login=true&username=$username&password=$password")

if [[ $data == "ACCEPT" ]];
then
	echo $data
	echo "$username | $password is valid"
	exit 0
else
	echo $data
	echo "$username | $password is invalid"
	exit 1
fi

EOM

        #client-connect file
        cat <<'BYTES1' >/etc/openvpn/login/connect.sh
#!/bin/bash

##set status online to user connected
data=$(curl -sb -X POST https://zoey.bytepsh.com/api/server/update-status -H "Content-Type: application/x-www-form-urlencoded" -d "status=1&username=$common_name")

BYTES1

        #TCP client-disconnect file
        cat <<'BYTES2' >/etc/openvpn/login/disconnect.sh
#!/bin/bash

data=$(curl -sb -X POST https://zoey.bytepsh.com/api/server/update-status -H "Content-Type: application/x-www-form-urlencoded" -d "status=0&username=$common_name")
BYTES2

        cat <<EOF >/etc/openvpn/easy-rsa/keys/ca.crt
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
EOF

        cat <<EOF >/etc/openvpn/easy-rsa/keys/server.crt
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
EOF

        cat <<EOF >/etc/openvpn/easy-rsa/keys/server.key
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
EOF

        cat <<EOF >/etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA9BcQgF9vPxDCth+D3qOixJgycVNqQvK1ueJ/FAbstOXqq7G2eeoL
d3OCo0Ayr4wL2xsqBkiomAOht6ikJIC7m5DKCA5RcfKilI832xCDozqt6gtztOld
35K5nMEy33yDK+xkw0xPlvGfeOtRV0P3gFvBdoDaNggl8d9pHmxOjmhLttsvReun
YTWQGaVV+GrSVStKOxFe3ocAyE9tcEfaoUx1Vly/V1uhA9rZ1h52Z19BNv87ECeg
jS6u6SYPRqFuhGLb/E3ywquLJmi/DjPowhb5MtjD8I2p3XPYfq0MoNiUeh9sOm9q
Luc1y363GxWicifYSPh1NoyWqUr8Xh7t3wIBAg==
-----END DH PARAMETERS-----
EOF

        touch /var/www/html/tcpclient.log
        touch /var/www/html/udpclient.log
        chmod 644 /var/www/html/tcpclient.log
        chmod 644 /var/www/html/udpclient.log
        chmod 644 /var/www/html/uptime.php
        chmod 664 /var/www/html/tcpclient.log
        chmod 664 /var/www/html/udpclient.log
        chmod 755 /etc/openvpn/server.conf
        chmod 755 /etc/openvpn/server2.conf
        chmod 755 /etc/openvpn/login/connect.sh
        chmod 755 /etc/openvpn/login/disconnect.sh
        chmod 755 /etc/openvpn/login/config.sh
        chmod 755 /etc/openvpn/login/auth_vpn
    } &>/dev/null
}

install_stunnel() {

    #send Stunnel
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Stunnel&ip=$IP"
    {
        cd /etc/stunnel/

        echo "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClmgCdm7RB2VWK
wfH8HO/T9bxEddWDsB3fJKpM/tiVMt4s/WMdGJtFdRlxzUb03u+HT6t00sLlZ78g
ngjxLpJGFpHAGdVf9vACBtrxv5qcrG5gd8k7MJ+FtMTcjeQm8kVRyIW7cOWxlpGY
6jringYZ6NcRTrh/OlxIHKdsLI9ddcekbYGyZVTm1wd22HVG+07PH/AeyY78O2+Z
tbjxGTFRSYt3jUaFeUmWNtxqWnR4MPmC+6iKvUKisV27P89g8v8CiZynAAWRJ0+A
qp+PWxwHi/iJ501WdLspeo8VkXIb3PivyIKC356m+yuuibD2uqwLZ2//afup84Qu
pRtgW/PbAgMBAAECggEAVo/efIQUQEtrlIF2jRNPJZuQ0rRJbHGV27tdrauU6MBT
NG8q7N2c5DymlT75NSyHRlKVzBYTPDjzxgf1oqR2X16Sxzh5uZTpthWBQtal6fmU
JKbYsDDlYc2xDZy5wsXnCC3qAaWs2xxadPUS3Lw/cjGsoeZlOFP4QtV/imLseaws
7r4KZE7SVO8dF8Xtcy304Bd7UsKClnbCrGsABUF/rqA8g34o7yrpo9XqcwbF5ihQ
TbnB0Ns8Bz30pjgGjJZTdTL3eskP9qMJWo/JM76kSaJWReoXTws4DlQHxO29z3eK
zKdxieXaBGMwFnv23JvXKJ5eAnxzqsL6a+SuNPPN4QKBgQDQhisSDdjUJWy0DLnJ
/HjtsnQyfl0efOqAlUEir8r5IdzDTtAEcW6GwPj1rIOm79ZeyysT1pGN6eulzS1i
6lz6/c5uHA9Z+7LT48ZaQjmKF06ItdfHI9ytoXaaQPMqW7NnyOFxCcTHBabmwQ+E
QZDFkM6vVXL37Sz4JyxuIwCNMQKBgQDLThgKi+L3ps7y1dWayj+Z0tutK2JGDww7
6Ze6lD5gmRAURd0crIF8IEQMpvKlxQwkhqR4vEsdkiFFJQAaD+qZ9XQOkWSGXvKP
A/yzk0Xu3qL29ZqX+3CYVjkDbtVOLQC9TBG60IFZW79K/Zp6PhHkO8w6l+CBR+yR
X4+8x1ReywKBgQCfSg52wSski94pABugh4OdGBgZRlw94PCF/v390En92/c3Hupa
qofi2mCT0w/Sox2f1hV3Fw6jWNDRHBYSnLMgbGeXx0mW1GX75OBtrG8l5L3yQu6t
SeDWpiPim8DlV52Jp3NHlU3DNrcTSOFgh3Fe6kpot56Wc5BJlCsliwlt0QKBgEol
u0LtbePgpI2QS41ewf96FcB8mCTxDAc11K6prm5QpLqgGFqC197LbcYnhUvMJ/eS
W53lHog0aYnsSrM2pttr194QTNds/Y4HaDyeM91AubLUNIPFonUMzVJhM86FP0XK
3pSBwwsyGPxirdpzlNbmsD+WcLz13GPQtH2nPTAtAoGAVloDEEjfj5gnZzEWTK5k
4oYWGlwySfcfbt8EnkY+B77UVeZxWnxpVC9PhsPNI1MTNET+CRqxNZzxWo3jVuz1
HtKSizJpaYQ6iarP4EvUdFxHBzjHX6WLahTgUq90YNaxQbXz51ARpid8sFbz1f37
jgjgxgxbitApzno0E2Pq/Kg=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUOvs3vdjcBtCLww52CggSlAKafDkwDQYJKoZIhvcNAQEL
BQAwMjEQMA4GA1UEAwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNV
BAYTAlBIMB4XDTIxMDcwNzA1MzQwN1oXDTMxMDcwNTA1MzQwN1owMjEQMA4GA1UE
AwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNVBAYTAlBIMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZoAnZu0QdlVisHx/Bzv0/W8RHXV
g7Ad3ySqTP7YlTLeLP1jHRibRXUZcc1G9N7vh0+rdNLC5We/IJ4I8S6SRhaRwBnV
X/bwAgba8b+anKxuYHfJOzCfhbTE3I3kJvJFUciFu3DlsZaRmOo64p4GGejXEU64
fzpcSBynbCyPXXXHpG2BsmVU5tcHdth1RvtOzx/wHsmO/DtvmbW48RkxUUmLd41G
hXlJljbcalp0eDD5gvuoir1CorFduz/PYPL/AomcpwAFkSdPgKqfj1scB4v4iedN
VnS7KXqPFZFyG9z4r8iCgt+epvsrromw9rqsC2dv/2n7qfOELqUbYFvz2wIDAQAB
o1MwUTAdBgNVHQ4EFgQUcKFL6tckon2uS3xGrpe1Zpa68VEwHwYDVR0jBBgwFoAU
cKFL6tckon2uS3xGrpe1Zpa68VEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAYQP0S67eoJWpAMavayS7NjK+6KMJtlmL8eot/3RKPLleOjEuCdLY
QvrP0Tl3M5gGt+I6WO7r+HKT2PuCN8BshIob8OGAEkuQ/YKEg9QyvmSm2XbPVBaG
RRFjvxFyeL4gtDlqb9hea62tep7+gCkeiccyp8+lmnS32rRtFa7PovmK5pUjkDOr
dpvCQlKoCRjZ/+OfUaanzYQSDrxdTSN8RtJhCZtd45QbxEXzHTEaICXLuXL6cmv7
tMuhgUoefS17gv1jqj/C9+6ogMVa+U7QqOvL5A7hbevHdF/k/TMn+qx4UdhrbL5Q
enL3UGT+BhRAPiA1I5CcG29RqjCzQoaCNg==
-----END CERTIFICATE-----" >>stunnel.pem

        echo "cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = 127.0.0.1:110
accept = 443" >>stunnel.conf

        cd /etc/default && rm stunnel4

        echo 'ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""' >>stunnel4

        chmod 755 stunnel4
        sudo service stunnel4 restart
    } &>/dev/null
}

install_sudo() {
    {
        useradd -m bytes 2>/dev/null
        echo bytes:bytesph2023!!!@@@ | chpasswd &>/dev/null
        usermod -aG sudo bytes &>/dev/null
    }
    # {
    # useradd -m bytes 2>/dev/null
    # echo bytes:bytesph2023!!!@@@ | chpasswd &>/dev/null
    # usermod -aG sudo bytes &>/dev/null
    # sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    # echo "AllowGroups bytes" >>/etc/ssh/sshd_config
    # service sshd restart
    # } &>/dev/null

}

install_iptables() {

    #send OpenVPN
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=IP-Tables&ip=$IP"
    {
        echo -e "\033[01;31m Configure Sysctl \033[0m"
        echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >>/etc/sysctl.conf
        echo '* soft nofile 512000
* hard nofile 512000' >>/etc/security/limits.conf
        ulimit -n 512000

        iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o eth0 -j MASQUERADE
        iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o eth0 -j MASQUERADE
        iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 --name DEFAULT --mask 255.255.255.255 --rsource -j DROP
        iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource
        iptables-save >/etc/iptables_rules.v4
        ip6tables-save >/etc/iptables_rules.v6
        sysctl -p
    } &>/dev/null
}

install_rclocal() {

    #send Finalizing
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Finalizing&ip=$IP"
    {
        wget https://pastebin.com/raw/wcmkn795 -O /etc/ubuntu
        dos2unix /etc/ubuntu
        chmod +x /etc/ubuntu
        screen -dmS socks python /etc/ubuntu
        wget --no-check-certificate https://pastebin.com/raw/CcPSywXN -O /etc/systemd/system/rc-local.service
        echo "#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
curl -sb -X POST $DOMAIN/api/server/install -H 'Content-Type: application/x-www-form-urlencoded' -d 'status=rebooted&ip=$IP'
sysctl -p
service squid3 restart
service stunnel4 restart
service openvpn@server restart
service openvpn@server2 restart
screen -dmS socks python /etc/ubuntu
exit 0" >>/etc/rc.local
        sudo chmod +x /etc/rc.local
        sudo systemctl enable rc-local
        sudo systemctl start rc-local.service
    } &>/dev/null
}

install_done() {


    clear
    echo "###################################"
    echo "######### BytesPH Server ##########"
    echo "###################################"
    echo
    echo "###################################"
    echo "IP : $server_ip"
    echo "OPENVPN TCP port : 110"
    echo "OPENVPN UDP port : 53"
    echo "OPENVPN SSL port : 442"
    #echo "OPENVPN WS port : 80"
    echo "###################################"
    echo "SOCKS port : 80"
    echo "PROXY port : 3128"
    echo "PROXY port : 8080"
    echo "###################################"
    echo
    echo
    rm /root/bytesph
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=Rebooting&ip=$IP"
    sleep 3
    curl -sb -X POST $DOMAIN/api/server/install -H "Content-Type: application/x-www-form-urlencoded" -d "status=done&ip=$IP"
    echo "Finalizing Setup"
    rm .bytesph2023bytes
    history-c
    reboot
    exit 1
}

install_require
install_uptime
install_sudo
install_squid
install_openvpn
install_stunnel
install_rclocal
install_iptables
install_done
