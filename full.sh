#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run this as root"
  exit
fi

systemctl stop ufw
systemctl disable ufw

BRC="139.162.102.145"

iptables -I INPUT -m state -s 0.0.0.0/0 -p all --state ESTABLISHED,RELATED -j ACCEPT

# Block some Layer3 Protocols
# Helps fight off ESP/GRE/AH floods
# If you need these protocols - uncomment these rules,
# or set PBA variable to ACCEPT
iptables -t raw -A PREROUTING -p esp -j REJECT --reject-with tcp-reset
iptables -t raw -A PREROUTING -p gre -j REJECT --reject-with tcp-reset
iptables -t raw -A PREROUTING -p ah -j REJECT --reject-with icmp-proto-unreachable


# Explicitly drop invalid traffic
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# Block bogus TCP flags
# Helps fight off TCP Null Attack, TCP XMAS Attack,
# And other attack types with invalid TCP Flags.
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP

# Block LAND and BLAT Attack
iptables -t raw -I PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

# Block zero-length TCP and UDP
# Helps fight off UDP-NULL, TCP-NULL attacks
iptables -t raw -I PREROUTING -p tcp -m length --length 0 -j DROP
# iptables -t raw -I PREROUTING -p udp -m length --length 0 -j DROP

# Drop UDP and TCP packets with incorrect source port
iptables -t raw -I PREROUTING -p tcp ! --sport 0:65535 -j DROP
# iptables -t raw -I PREROUTING -p udp ! --sport 0:65535 -j DROP

# Drop all fragmented packets
# Helps fight off fragmented floods
iptables -t raw -I PREROUTING -f -j DROP

# Block invalid SNMP Length
iptables -t raw -A PREROUTING -p udp --sport 161 -m length --length 2536 -j DROP
iptables -t raw -A PREROUTING -p udp --sport 161 -m length --length 1244 -j DROP

# Block new packets that not SYN
# And block pattern of most used ACK Flood type
# Helps fight off TCP ACK/FIN/RST floods
iptables -t mangle -I PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
iptables -t raw -I PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP

# Block unusual TCP MSS Value
iptables -t mangle -I PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

# Block SYN sPort less than 1024
iptables -t raw -I PREROUTING -p tcp --syn ! --sport 1024:65535 -j DROP

# Block port scanners (stealth also)
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP

# OVH Bypass payload
iptables -t raw -A PREROUTING -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6" -j DROP

# SAO-UDP Bypass payload
# iptables -t raw -A PREROUTING -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP

# TCP Patches
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED -j DROP

# Botnet Attack filters
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "2&0xFFFF=0x2:0x0100" -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "12&0xFFFFFF00=0xC0A80F00" -j DROP
iptables -t raw -A PREROUTING -p tcp -syn -m length --length 52 u32 --u32 "12&0xFFFFFF00=0xc838" -j DROP
iptables -t raw -A PREROUTING -p udp -m length --length 28 -m string --algo bm --string "0x0010" -j DROP
iptables -t raw -A PREROUTING -p udp -m length --length 28 -m string --algo bm --string "0x0000" -j DROP
iptables -t raw -A PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0020" -j DROP
iptables -t raw -A PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0c54" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK ACK -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED -j DROP
iptables -t mangle -A PREROUTING -p tcp -syn -m length --length 52 -m string --algo bm --string "0xc838" -m state --state ESTABLISHED -j DROP

# Suspicious string filters
iptables -t raw -A PREROUTING -m string --algo bm --string "CRI" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "STD" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "std" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "SAAM" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "ddos" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "flood" -j DROP

# Sophiscated NULL method patches
iptables -t raw -A PREROUTING -m string --algo bm --string "0x00000" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "0x000000000001" -j DROP

# NTP Reflection block
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "0>>22&0x3C@8" -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "0>>22&0x3C@8&0xFF=42" -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "0>>22&0x3C@8&0xFF" -j DROP

# Block private bypasses
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|424f4f5445524e4554|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|41545441434b|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|504r574552|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|6c6e6f6172656162756e6386f6673b694464696573|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|736b6954|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -t raw -A PREROUTING -p udp -m multiport --dports 16000:29000,22 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP
iptables -t raw -A PREROUTING -p udp --dport 16000:29000 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP
iptables -t raw -A PREROUTING -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "6&0xFF=0,2:5,7:16,18:255" -j DROP
iptables -t raw -A PREROUTING -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -t raw -A PREROUTING -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "28 & 0x00FF00FF = 0x00200020 && 32 & 0x00FF00FF = 0x00200020 && 36 & 0x00FF00FF = 0x00200020 && 40 & 0x00FF00FF = 0x00200020" -j DROP
iptables -t raw -A PREROUTING -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP 

# Set syn proxy
iptables -I PREROUTING -p tcp -m tcp --dport 1:65535 --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack
iptables -I INPUT -p tcp -m tcp --dport 1:65535 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -I INPUT -p tcp -m tcp --dport 1:65535 -m state --state INVALID -j DROP

modprobe ip_conntrack

sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
sysctl -w net/netfilter/nf_conntrack_max=2000000

sh -c 'echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize'

iptables -t nat -A PREROUTING -p tcp --dport 23:65534 -j DNAT --to-destination "$BRC"
iptables -t nat -A PREROUTING -p tcp --dport 1:21 -j DNAT --to-destination "$BRC"
iptables -t nat -A POSTROUTING -j MASQUERADE

# Apply sysctl
cp ./sysctl.conf /etc
sysctl -p

echo -e "Script changes applied, but iptables rules are not saved.
Check the network now, and if it works, save the rules manually with sudo 'netfilter-persistent save'\n"
echo -e "Also, you can check some info about rules (example: dropped packets),
With 'nft list ruleset'"
exit 0;
