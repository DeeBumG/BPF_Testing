import subprocess

GATEWAY_IP = "172.16.1.1"
DEV_NAME   = "enp175s0f0np0"

cmds = []
counter = 0
with open("routeviews-rv2-20230211-1200.pfx2as") as f:
    for line in f:
        if counter < 45465 or counter > 48788:
            prefix, plen = line.split()[:2]
            cmds.append(f"route add {prefix}/{plen} via {GATEWAY_IP} dev {DEV_NAME} onlink\n")
        counter += 1

cmds.append(f"route add 28.0.0.0/8 via {GATEWAY_IP} dev {DEV_NAME} onlink\n")

p = subprocess.Popen(["ip", "-batch", "-"], stdin=subprocess.PIPE, text=True)
p.communicate("".join(cmds))
print(f"submitted {len(cmds)} routes, ip exited with {p.returncode}")
