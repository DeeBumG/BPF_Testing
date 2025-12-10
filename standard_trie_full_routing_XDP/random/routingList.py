import os

GATEWAY_IP = "172.16.1.1"
DEV_NAME = "enp175s0f0"
ROUTE_ADD1 = "ip route add"
ROUTE_ADD2 = "via " + GATEWAY_IP

counter = 0

with open("routeviews-rv2-20230211-1200.pfx2as") as file:
    for line in file:
        if counter < 45465 or counter > 48788:
            print(ROUTE_ADD1 + " " + line.split()[0] + "/" + line.split()[1] + " " + ROUTE_ADD2 + " dev " + DEV_NAME)
            os.system(ROUTE_ADD1 + " " + line.split()[0] + "/" + line.split()[1] + " " + ROUTE_ADD2 + " dev " + DEV_NAME)
            counter += 1
        else:
            counter += 1

os.system("sudo ip route add 28.0.0.0/8 via 172.16.1.1 dev enp175s0f0")
