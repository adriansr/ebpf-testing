### EBPF Port filtering demo ###

A simple EBPF program in C that builds outside the kernel
and installs as a qdisc classifier. It drops all TCP packets
that don't have port 80 as source or destination.

Usage
=====
 
Build the EBPF module

    $ make

source the script, as root

    $ sudo su

    # source ./test_mido_cls.sh

Start the test. Creates a veth-pair with one end on a namespace
using address 10.123.45.2 and installs the ebpf filter.
Launches HTTP servers at port 80 and 81. Only 80 should be reachable.

    # start

test connectivity to namespace, for example

    # curl http://10.123.45.2/

    # curl http://10.123.45.2:81/

First will work by printing a directory listing in HTML.
The second will stall as TCP SYN packets are silently dropped
and the classifier output will be printed:

     curl-1874  [000] .Ns1   118.346273: : MIDO: Dropped packet from: a7b2d01:57332
     curl-1874  [000] .Ns1   118.346337: : MIDO:                  to: a7b2d02:81

When done with the testing, remove devices and namespaces

    # stop

Sources
=======

* iproute2's BPF sample http://code.metager.de/source/xref/linux/utils/iproute2/examples/bpf/bpf_prog.c
* samples/bpf/test_cls_bpf.sh from Linux kernel https://github.com/torvalds/linux/blob/master/samples/bpf/test_cls_bpf.sh

