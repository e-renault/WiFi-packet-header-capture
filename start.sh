#! /bin/bash
sudo service NetworkManager stop
sudo ip link set wlp2s0 down
sudo iwconfig wlp2s0 mode monitor
sudo ip link set wlp2s0 up
