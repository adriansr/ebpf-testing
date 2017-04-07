#!/bin/bash
#
# Usage:
# 
# 1. source this script
#
#   # source ./test_mido_cls.sh
#
# 2. start it. Creates a veth-pair with one end on a namespace
#    using address 10.123.45.2 and installs the ebpf filter.
#    Launches HTTP servers at port 80 and 81. Only 80 should be
#    reachable.
#
#   # start
#
# 3. test connectivity to namespace
#
#   # curl http://10.123.45.2/
#   # curl http://10.123.45.2:81/
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

function __setup {
    echo -n "Loading bpf program '$2'... "
    ip netns exec $NS tc qdisc add dev pair_$IFC clsact
    ip netns exec $NS tc filter add dev pair_$IFC ingress bpf da obj $1 sec $2
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
    __setup ./parse_mido_80.o classifier
    ip netns exec $NS python -m SimpleHTTPServer 80 &
    ip netns exec $NS python -m SimpleHTTPServer 81 &
    cat "$TRACEFILE"_pipe &
    PIPE_PID="$!"
}

function stop {
    test ! -z "$PIPE_PID" && kill $PIPE_PID
    tc qdisc del dev $IFC clsact
    ip link del dev $IFC
    ip netns pids $NS | xargs kill
    ip netns del $NS
}

