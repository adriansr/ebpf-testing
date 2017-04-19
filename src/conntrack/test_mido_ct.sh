#!/bin/bash
#
# Usage:
# 
# 1. source this script
#
#   # source ./test_mido_ct.sh
#
# 2. start it. Creates a veth-pair with one end on a namespace
#    using address 10.123.45.2 and installs the ebpf filter.
#
#   # start
#
# 3. test connectivity to namespace
#
# 4. remove devices and namespaces
#
#   # stop
#

IFC=test_veth
NS=test_bpf
IP_OUT=10.123.45.1/30
IP=10.123.45.2/30
TRACEFILE=/sys/kernel/debug/tracing/trace
SOCKET=/tmp/bpf-sock

function __setup {
    echo "Launching agent ..."
    rm "$SOCKET"
    ./agent "$SOCKET" &
    AGENT_PID=$!
    sleep 2
    if [ ! -e "$SOCKET" ]
    then
        echo "Agent failed!" >&2
        return 1
    fi
    echo -n "Loading bpf program '$2'... "
    ip netns exec $NS tc qdisc add dev pair_$IFC clsact
    ip netns exec $NS strace tc filter add dev pair_$IFC ingress bpf obj $1 sec filter-in #export $SOCKET
    ip netns exec $NS strace tc filter add dev pair_$IFC egress bpf obj $1 sec filter-out #export $SOCKET
    local status=$?
    if [ $status -ne 0 ]; then
        echo "FAIL"
    else
        echo "ok"
    fi
}

function start {
    test -w $TRACEFILE && ( echo -n > $TRACEFILE )
    ip link add name $IFC type veth peer name pair_$IFC
    ip link set $IFC up
    ip netns add $NS
    ip link set netns $NS dev pair_$IFC
    ip netns exec $NS ip link set up dev lo
    ip netns exec $NS ip link set pair_$IFC up
    ip address add $IP_OUT dev $IFC
    ip netns exec $NS ip address add $IP dev pair_$IFC
    __setup bpf_conntrack.o
    ip netns exec $NS python -m SimpleHTTPServer 80 &
    cat "$TRACEFILE"_pipe &
    PIPE_PID="$!"
}

function stop {
    test ! -z "$PIPE_PID" && kill $PIPE_PID
    test ! -z "$AGENT_PID" && kill $AGENT_PID
    tc qdisc del dev $IFC clsact
    ip netns pids $NS | xargs kill
    ip link del dev $IFC
    ip netns del $NS
}

