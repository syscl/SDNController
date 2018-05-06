#!/bin/sh

# alternative high performance way to execute python script by pypy
# ./pypy ~/github/pox/pox.py log.level --DEBUG proto.dhcpd --network=10.0.1.0/24 --ip=10.0.1.1 SDN_Controller
#./pox.py log.level --DEBUG proto.dhcpd --network=10.5.2.0/24 --ip=10.6.2.1 SDN_Controller
./pox.py log.level --DEBUG proto.dhcpd --network=10.0.1.0/24 --ip=10.0.1.1 SDN_Controller

exit 0
