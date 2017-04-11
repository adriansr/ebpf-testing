### EBPF conntrack demo ###

A simple EBPF program in C that only allows traffic if the
inverse 5-tuple has been seen recently.

Usage
=====
 
Build the EBPF module

    $ make

source the script, as root

    $ sudo su

    # source ./test_mido_ct.sh

Start the test. Creates a veth-pair with one end on a namespace
using address 10.123.45.2 and installs the ebpf filter.

    # start

test connectivity to namespace, for example

    TODO

When done with the testing, remove devices and namespaces

    # stop

Sources
=======

* iproute2's BPF sample http://code.metager.de/source/xref/linux/utils/iproute2/examples/bpf/bpf_prog.c
* samples/bpf/test_cls_bpf.sh from Linux kernel https://github.com/torvalds/linux/blob/master/samples/bpf/test_cls_bpf.sh

