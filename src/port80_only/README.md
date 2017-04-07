Usage:
 
1. source this script

    # source ./test_mido_cls.sh

2. start it. Creates a veth-pair with one end on a namespace
   using address 10.123.45.2 and installs the ebpf filter.
   Launches HTTP servers at port 80 and 81. Only 80 should be
   reachable.

    # start

3. test connectivity to namespace

    # curl http://10.123.45.2/
    # curl http://10.123.45.2:81/

4. remove devices and namespaces

    # stop

