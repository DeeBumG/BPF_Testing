sudo ip addr add 172.16.1.2/30 dev enp175s0f0
sudo ip addr add 172.16.1.6/30 dev enp175s0f1
sudo ip addr add 172.16.2.2/24 dev eno1
sudo ip link set enp175s0f0 up
sudo ip link set enp175s0f1 up
sudo ip link set eno1 up

sudo sysctl -w net.ipv4.ip_forward=1

sudo arp -s 172.16.1.1 e8:ea:6a:2a:c3:7a
sudo arp -s 172.16.1.5 e8:ea:6a:2a:c3:7b

sudo ethtool -K enp175s0f0 rx off tx off tso off sg off gso off receive-hashing on
sudo ethtool -K enp175s0f1 rx off tx off tso off sg off gso off receive-hashing on

sudo python3 routingList.py
