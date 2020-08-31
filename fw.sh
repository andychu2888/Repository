#!/bin/bash


firewall_iptables(){
    ### first flush all the iptables Rules
    iptables -F


    # INPUT iptables Rules
    # Accept loopback input
    iptables -A INPUT -i lo -p all -j ACCEPT

    # allow 3 way handshake
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    ### DROPspoofing packets
    iptables -A INPUT -s 10.0.0.0/8 -j DROP 
    iptables -A INPUT -s 169.254.0.0/16 -j DROP
    iptables -A INPUT -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -s 127.0.0.0/8 -j DROP
    iptables -A INPUT -s 192.168.0.0/24 -j DROP

    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    #for SMURF attack protection
    iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
    iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
    #iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second --limit-burst 2 -j ACCEPT

    # Droping all invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # flooding of RST packets, smurf attack Rejection
    iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

    # Protecting portscans
    # Attacking IP will be locked for 24 hours X 30 days X10(3600 x 24 x 30 X 10 = 25920000 Seconds)
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 25920000 -j DROP
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 25920000 -j DROP

    # Remove attacking IP after 10 months
    iptables -A INPUT -m recent --name portscan --remove
    iptables -A FORWARD -m recent --name portscan --remove

    # These rules add scanners to the portscan list, and log the attempt.
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

    iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
    iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

    # Allow the following ports through from outside
    iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 111 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 111 -j ACCEPT


    # block ping means ICMP port is close (If you do not want ping replace ACCEPT with REJECT)
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP

    # Lastly DROP All INPUT traffic
    iptables -A INPUT -j DROP

}

main(){
    firewall_iptables
   
}

main

