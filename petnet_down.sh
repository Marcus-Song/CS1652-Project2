set -x

sudo ip link set dev petnet_tap1 down
sudo ip link set dev petnet_bridge down
sudo ip tuntap del dev petnet_tap1 mode tap
sudo ip link delete petnet_bridge type bridge
