#!/bin/bash

iptables -t nat -A INPUT -s 192.168.100.199 -d 192.187.9.98 -j ACCEPT
iptables -t nat -A INPUT -s 192.168.100.99 -j ACCEPT
iptables -A INPUT -t nat -s 192.168.100.99 -j DROP
iptables -A INPUT -i eth0 -p icmp -j DROP
iptables -A INPUT -s 192.168.100.500 -j DROP
iptables -A INPUT -s 192.168.100.500 -d 192.168.100.6 -j ACCEPT
iptables -A INPUT -p udp -s 192.168.100.5 -d 192.168.100.6 -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.100.4 --sport 80 -j DROP
iptables -A FORWARD -p tcp -s 192.168.100.3 --sport 80 -d 192.168.100.4 --dport 90 -j REJECT
iptables -A INPUT -p tcp -s 192.168.100.2 --sport 80 -d 192.168.100.3 --dport 90 -j REJECT
iptables -A INPUT -p icmp -s 192.168.100.1 -j ACCEPT
iptables -A INPUT -p UDP -s 192.168.100.100 --sport 80:900 -d 192.190.39.02 -j DROP
iptables -A INPUT -p UDP -s 192.168.100.100 --sport 80 -d 192.190.39.02 -j DROP

