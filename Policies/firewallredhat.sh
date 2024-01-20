#!/bin/bash
# @(#) iptables.sh - Script for configuring firewall with iptables
# Based on: http://centossrv.com/
# Modified from the author heartnet
# Reference: https://gist.github.com/heartnet/921615
#
#
# Configuration part
#
##############################

## Set external interface
## use command "ip a" to find your interfaces
EXTERNAL_IF="eth0"

## Run this as a script under the root account like:
## /root/iptables.sh
## Make sure the file has execute permissions
## sudo chmod 755 /root/iptables.sh
## Define full path of functions
## create the scripts folder and files
## mkdir /root/scripts
## touch /root/scripts/iptables_functions
## touch /root/scripts/blacklist
## touch /root/scripts/whitelist
## touch /root/scripts/allow_proxy_list

## iptable functions
PATH_FUNCTIONS="/root/scripts/iptables_functions"

## Define full path of blacklist
PATH_BLACKLIST="/root/scripts/misc/blacklist"

## Define full path of whitelist
PATH_WHITELIST="/root/scripts/misc/whitelist"

## Define full path of allowed host or network to use proxy
PATH_ALLOW_PROXY_LIST="/root/scripts/allow_proxy_list"

## Define full path of init script of iptables
## find the iptables binary using the locate command
## replace the path with the correct path
PATH_INIT_SCRIPT="/etc/init.d/iptables"
PATH_INIT_SCRIPT="/usr/sbin/iptables"

## Define syslog priority of iptables
SYSLOG_PRIORITY="debug"

## Define country which is allowed to access
COUNTRY_ACCEPT=("US")

## Define country of which packets are forcibly dropped
COUNTRY_DROP=("CN" "TW" "KR" "KP")

## set PATH
export PATH=/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin


#
# Main routines
#
##############################

## Obtain netmask from target interface
LOCALNET_MASK=`ifconfig ${EXTERNAL_IF} | sed -e 's/^.*Mask:\([^ ]*\)$/\1/p' -e d`

## Obtain network address from target interface
LOCALNET_ADDR=`netstat -rn | grep ${EXTERNAL_IF} | grep ${LOCALNET_MASK} | cut -f1 -d' '`
LOCALNET=${LOCALNET_ADDR}/${LOCALNET_MASK}

## Reset all rules
iptables -F
iptables -X
iptables -Z

## Stop running iptables
## ${PATH_INIT_SCRIPT} stop

## Default policy
## (These policies will be applied to rules which do not match any rules.)
iptables -P INPUT   DROP   # All discard incoming packets
#iptables -P OUTPUT  ACCEPT # All permit outgoing packets
#iptables -P FORWARD ACCEPT # All permit forwarding packets
#iptables -P FORWARD DROP   # All discard forwarding packets
iptables -P OUTPUT  DROP # drop all outgoing packets
iptables -P FORWARD DROP # drop all forwarding packets

## Permit all packets from loopback interface
iptables -A INPUT -i lo -j ACCEPT

## Permit all packets from private network
iptables -A INPUT -s ${LOCALNET} -j ACCEPT

## Permit all packets via private network interface card
iptables -A INPUT ! -i ${EXTERNAL_IF} -j ACCEPT

## Permit all return packets from private network
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


## Enable these if the OUTPUT POLICY IS SET TO DROP BY DEFAULT
## Permit all packets from loopback interface
iptables -A OUTPUT -i lo -j ACCEPT

## Permit all packets from private network
iptables -A OUTPUT -s ${LOCALNET} -j ACCEPT

## Permit all packets via private network interface card
iptables -A OUTPUT ! -i ${EXTERNAL_IF} -j ACCEPT

## Permit all return packets from private network
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


## Enable SYN Cookies
## (*) for TCP SYN Flood attack
sysctl -w net.ipv4.tcp_syncookies=1  >/dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1"  >>/etc/sysctl.conf

## Do not reply to broadcast ping packets
## (*) for Smurf attack
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  >/dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1"  >>/etc/sysctl.conf

## Deny all ICMP Redirect packets
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for DEV in `ls /proc/sys/net/ipv4/conf/`
do
	sysctl -w net.ipv4.conf.${DEV}.accept_redirects=0  >/dev/null
	echo "net.ipv4.conf.${DEV}.accept_redirects=0"  >>/etc/sysctl.conf
done

## Deny all Source-Routed packets
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for DEV in `ls /proc/sys/net/ipv4/conf/`
do
	sysctl -w net.ipv4.conf.${DEV}.accept_source_route=0  >/dev/null
	echo "net.ipv4.conf.${DEV}.accept_source_route=0"  >>/etc/sysctl.conf
done

## Discard all packets of new sessions which do not start from SYN flag
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

## Deny all packets of new sessions which start from SYN/ACK flag
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset

## Discard all fragmented packets after logging
iptables -A INPUT -f -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [FRAGMENT] : "
iptables -A INPUT -f -j DROP

## Discard all packets which are related to NetBIOS from external network without logging
## (*) for not logging unnecessary packets
iptables -A INPUT  ! -s ${LOCALNET} -p tcp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A INPUT  ! -s ${LOCALNET} -p udp -m multiport --dports 135,137,138,139,445 -j DROP
iptables -A OUTPUT ! -d ${LOCALNET} -p tcp -m multiport --sports 135,137,138,139,445 -j DROP
iptables -A OUTPUT ! -d ${LOCALNET} -p udp -m multiport --sports 135,137,138,139,445 -j DROP

## Discard all private packets from external interface after logging
## (*) for Ingress
iptables -N INGRESS
iptables -A INGRESS -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [INGRESS_ATTACK]: "
iptables -A INPUT -i ${EXTERNAL_IF} -s 0.0.0.0/8      -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 127.0.0.0/8    -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 10.0.0.0/8     -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 172.16.0.0/12  -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 192.168.0.0/16 -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 169.254.0.0/16 -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 192.0.2.0/24   -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 224.0.0.0/4    -j INGRESS
iptables -A INPUT -i ${EXTERNAL_IF} -s 240.0.0.0/4    -j INGRESS

## Discard all private packets which go to outside from external interface after logging
## (*) for Egress
iptables -N EGRESS
iptables -A EGRESS -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [EGRESS_ATTACK]: "
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 0.0.0.0/8      -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 127.0.0.0/8    -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 10.0.0.0/8     -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 172.16.0.0/12  -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 192.168.0.0/16 -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 169.254.0.0/16 -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 192.0.2.0/24   -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 224.0.0.0/4    -j EGRESS
iptables -A OUTPUT -o ${EXTERNAL_IF} -d 240.0.0.0/4    -j EGRESS

## Discard all packets which request over 4 times per second after logging
## (*) for TCP SYN Flood attack
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 10/s --limit-burst 20 -j RETURN
iptables -A SYN_FLOOD -m limit --limit 1/s  --limit-burst 10 -j LOG \
	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [SYN_FLOOD]: "
iptables -A SYN_FLOOD -j DROP
iptables -A INPUT     -p tcp --syn -j SYN_FLOOD

## Discard all private packets including multicast packets from external network after logging
## (*) for IP Spoofing
#iptables -N IP_SPOOFING
#iptables -A IP_SPOOFING -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [IP_SPOOFING]: "
#iptables -A IP_SPOOFING -j DROP
#iptables -A INPUT -i ${EXTERNAL_IF} -s 0.0.0.0/8      -j IP_SPOOFING
#iptables -A INPUT -i ${EXTERNAL_IF} -s 127.0.0.0/8    -j IP_SPOOFING
#iptables -A INPUT -i ${EXTERNAL_IF} -s 10.0.0.0/8     -j IP_SPOOFING
#iptables -A INPUT -i ${EXTERNAL_IF} -s 172.16.0.0/12  -j IP_SPOOFING
#iptables -A INPUT -i ${EXTERNAL_IF} -s 192.168.0.0/16 -j IP_SPOOFING

## Discard all ping packets which request over 4 times per second after logging
## (*) for Ping of Death attack
iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A PING_OF_DEATH -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [PING_OF_DEATH]: "
iptables -A PING_OF_DEATH -j DROP
iptables -A INPUT         -p icmp --icmp-type echo-request -j PING_OF_DEATH

## Discard all packets for all host (broadcast, multicast) without logging
## (*) for not logging unnecessary packets
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1       -j DROP

## Deny all pakcets to port 113 (IDENT)
## (*) for not delaying responses from mail servers
iptables -A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset

## Definition of the "ACCEPT_COUNTRY_MAKE" function
## Define user-defined chain to permit all pakcets from specified country
ACCEPT_COUNTRY_MAKE(){
	for ADDR in `cat /tmp/cidr.txt | grep ^$1 | awk '{ print $2 }'`
	do
		iptables -A ACCEPT_COUNTRY -s ${ADDR} -j ACCEPT
	done
}

## Definition of the "DROP_COUNTRY_MAKE" function
## Define user-defined chain to discard all packets from specified country
DROP_COUNTRY_MAKE(){
	for ADDR in `cat /tmp/cidr.txt | grep ^$1 | awk '{ print $2 }'`
	do
		iptables -A DROP_COUNTRY -s ${ADDR} -m limit --limit 1/s -j LOG \
			--log-tcp-options --log-ip-options \
			--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [DROPPED_COUNTRY]: "
		iptables -A DROP_COUNTRY -s ${ADDR} -j DROP
	done
}

## Obtain the list of IP addresses
. ${PATH_FUNCTIONS}
IPLISTGET

## Create user-defined chain ("ACCEPT_COUNTRY") to permit all packets from accepted country
iptables -N ACCEPT_COUNTRY
for COUNTRY in "${COUNTRY_ACCEPT[@]}"
do
	ACCEPT_COUNTRY_MAKE ${COUNTRY}
done

## From below, If you need to permit all packets from accepted country,
## you can specify "ACCEPT_COUNTRY" instead of "ACCEPT".

## Discard all packets from aggressive coutries after logging
iptables -N DROP_COUNTRY
for COUNTRY in "${COUNTRY_DROP[@]}"
do
	DROP_COUNTRY_MAKE ${COUNTRY}
done
iptables -A INPUT -j DROP_COUNTRY


#
# Configuration for public servecies [beginning]
#

## Permit all packets to TCP port 22 (SSH) only from accepted country
iptables -A INPUT -p tcp --dport 22 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT_COUNTRY

## Allow MySQL on localhost only
iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 3306 -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT

## Permit all packets to TCP/UDP port 53 (DNS)
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

## Permit all packets to TCP port 80 (HTTP)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

## Permit all packets to TCP port 443 (HTTPS)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

## Permit all packets to TCP port 25 (SMTP)
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -j ACCEPT

## Permit all packets to TCP port 587 (SMTP Submission)
iptables -A INPUT -p tcp --dport 587 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 587 -j ACCEPT

## Permit all packets to TCP port 465 (SMTPS) only from accepted country
iptables -A INPUT -p tcp --dport 465 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 465 -j ACCEPT_COUNTRY

## Permit all packets to TCP port 110 (POP3) only from accepted country
iptables -A INPUT -p tcp --dport 110 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 110 -j ACCEPT_COUNTRY

## Permit all packets to TCP port 995 (POP3S) only from accepted country
iptables -A INPUT -p tcp --dport 995 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 995 -j ACCEPT_COUNTRY

## Permit all packets to TCP port 143 (IMAP) only from accepted country
iptables -A INPUT -p tcp --dport 143 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 143 -j ACCEPT_COUNTRY

## Permit all packets to TCP port 993 (IMAPS) only from accepted country
iptables -A INPUT -p tcp --dport 993 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 993 -j ACCEPT_COUNTRY

## Permit all packets to TCP port 1723 (PPTP) only from accepted country
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT_COUNTRY
iptables -A OUTPUT -p tcp --dport 1723 -j ACCEPT_COUNTRY

## Permit all packets to GRE only from accepted country
iptables -A INPUT -p gre -j ACCEPT_COUNTRY
iptables -A OUTPUT -p gre -j ACCEPT_COUNTRY

## for NAT via PPTP
iptables -t nat -A POSTROUTING -s 192.168.255.0/24 -j MASQUERADE

## Permit all packets to TCP/UDP port 5154 - 5170 (BZFS)
#iptables -A INPUT -p tcp --dport 5154:5170 -j ACCEPT
#iptables -A INPUT -p udp --dport 5154:5170 -j ACCEPT


## Permit all packets to TCP port 10382 (Squid) only from allowed host or network
#if [ -s ${PATH_ALLOW_PROXY_LIST} ]; then
#	iptables -N ALLOW_PROXY
#	iptables -A ALLOW_PROXY -j ACCEPT
#
#	for ADDR in `cat ${PATH_ALLOW_PROXY_LIST}`
#	do  
#		iptables -A INPUT -s ${ADDR} -p tcp --dport 10382 -j ALLOW_PROXY
#	done
#fi

#
# Configuration for public servecies [end]
#


## Discard all packets from aggressive IP addresses or networks after logging
if [ -s ${PATH_BLACKLIST} ]; then
	iptables -N BLACKLIST
	iptables -A BLACKLIST -j LOG --log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [BLACKLIST]: "
	iptables -A BLACKLIST -j DROP

	for ADDR in `cat ${PATH_BLACKLIST}`
	do
		iptables -I INPUT -s ${ADDR} -j BLACKLIST
	done
fi

## Permit all packets from reliable IP addresses or networks
if [ -s ${PATH_WHITELIST} ]; then
	iptables -N WHITELIST
	iptables -A WHITELIST -j ACCEPT

	for ADDR in `cat ${PATH_WHITELIST}`
	do
		iptables -I INPUT -s ${ADDR} -j WHITELIST
	done
fi

## Discard all packets which did not match any rules above after logging
iptables -A INPUT   -m limit --limit 1/s -j LOG \
	--log-tcp-options --log-ip-options \
	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [DROPPED_INPUT]: "
iptables -A INPUT -j DROP
#iptables -A FORWARD -m limit --limit 1/s -j LOG \
#	--log-tcp-options --log-ip-options \
#	--log-level ${SYSLOG_PRIORITY} --log-prefix "iptables: [DROPPED_FORWARD]: "
#iptables -A FORWARD -j DROP

## Save rules
#${PATH_INIT_SCRIPT} save

## Start iptables
#${PATH_INIT_SCRIPT} start

# [EOF]