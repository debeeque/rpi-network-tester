#!/bin/bash
# Usage: setup_network.sh [ports|port <mon0|snd0>|dhcp|nodhcp]
#   ports   put every plugged-in test port into its namespace; nothing is served
#   port    one port, run by analyzer-port@<port>.service when the adapter appears
#   dhcp    serve DHCP and RA on the test ports
#   nodhcp  stop serving
#   no argument: ports and dhcp

RUN=/run/analyzer
PORTS="mon0 snd0"
mkdir -p $RUN

port_ns() {
    case $1 in
        mon0) echo analyzer_monitor ;;
        snd0) echo analyzer_sender ;;
        *) return 1 ;;
    esac
}

port_net() {
    case $1 in
        mon0) echo 1 ;;
        snd0) echo 2 ;;
    esac
}

in_ns() {
    ip -n "$2" link show dev "$1" >/dev/null 2>&1
}

setup_port() {
    local dev=$1 ns n
    ns=$(port_ns "$dev") || { echo "Error: unknown port $dev"; return 1; }
    n=$(port_net "$dev")
    [ -e /run/netns/$ns ] || ip netns add $ns || return 1
    ip -n $ns link set lo up

    if ! in_ns $dev $ns; then
        if [ ! -e /sys/class/net/$dev ]; then
            echo "Port $dev: adapter not plugged in"
            return 2
        fi
        ip link set dev $dev netns $ns || return 1
    fi

    # The kernel would otherwise keep soliciting routers on any network it is plugged into
    ip netns exec $ns sysctl -qw net.ipv6.conf.$dev.router_solicitations=0
    ip -n $ns addr replace 10.0.$n.10/24 dev $dev
    ip -n $ns -6 addr replace fd00:$n::10/64 dev $dev
    ip -n $ns link set $dev up
    echo "Port $dev ready in $ns."

    [ -e $RUN/dhcp ] && start_dhcp_port $dev
    return 0
}

stop_dhcp_port() {
    local pidf=$RUN/dnsmasq_$1.pid
    [ -s $pidf ] && kill $(cat $pidf) 2>/dev/null
    rm -f $pidf
}

start_dhcp_port() {
    local dev=$1 ns n
    ns=$(port_ns $dev)
    n=$(port_net $dev)
    stop_dhcp_port $dev
    in_ns $dev $ns || { echo "Port $dev: not set up, nothing served"; return 2; }
    # Addresses only: no router and no DNS, the device routes nowhere and a host keeps its own uplink
    ip netns exec $ns dnsmasq --interface=$dev --bind-interfaces \
        --dhcp-range=10.0.$n.20,10.0.$n.20,255.255.255.0,12h \
        --dhcp-range=fd00:$n::20,fd00:$n::20,slaac,64,12h --enable-ra --ra-param=$dev,0,0 \
        --dhcp-option=option:router --dhcp-option=option:dns-server --dhcp-option=option6:dns-server \
        --dhcp-leasefile=$RUN/dnsmasq_$dev.leases \
        --pid-file=$RUN/dnsmasq_$dev.pid || return 1
    echo "Port $dev: DHCP and RA active."
}

all_ports() {
    local rc=2 dev
    for dev in $PORTS; do
        setup_port $dev && rc=0
    done
    return $rc
}

start_dhcp() {
    local rc=2 dev
    touch $RUN/dhcp
    for dev in $PORTS; do
        in_ns $dev $(port_ns $dev) || setup_port $dev >/dev/null
        start_dhcp_port $dev && rc=0
    done
    return $rc
}

stop_dhcp() {
    local dev
    rm -f $RUN/dhcp
    for dev in $PORTS; do
        stop_dhcp_port $dev
    done
    echo "DHCP and RA stopped."
}

case "${1:-all}" in
    ports)  all_ports ;;
    port)   setup_port "$2" ;;
    dhcp)   start_dhcp ;;
    nodhcp) stop_dhcp ;;
    all)    all_ports; start_dhcp ;;
    *)      echo "Usage: $0 [ports|port <mon0|snd0>|dhcp|nodhcp]"; exit 1 ;;
esac
