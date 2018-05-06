#!/bin/sh

#echo [1] Simple
#echo [2] IPBase = 0
#printf "Enter the topology you want[1/2]"
#read -p ":"
#sudo mn --topo=linear,3 --mac --controller remote
sudo mn --topo=linear,3 --mac --controller remote -i 0

exit 0
