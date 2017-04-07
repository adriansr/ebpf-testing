Usage:
 
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

