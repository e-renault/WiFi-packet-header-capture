#! /bin/bash
sudo ip link set wlp2s0 down
sudo iwconfig wlp2s0 mode managed
sudo ip link set wlp2s0 up
sudo service NetworkManager start
