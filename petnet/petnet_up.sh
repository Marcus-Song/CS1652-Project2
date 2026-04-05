set -x

sudo ip link add name petnet_bridge type bridge
sudo ip tuntap add dev petnet_tap1 mode tap user cs1652
sudo ip link set petnet_tap1 master petnet_bridge
sudo ip addr add 192.168.201.1/24 brd + dev petnet_bridge
sudo ip link set dev petnet_bridge up
sudo ip link set dev petnet_tap1 up
sudo ip link set petnet_bridge address a6:94:0d:b7:92:e9
