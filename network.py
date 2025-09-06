from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

interface = "eth0"

b = BPF(src_file="network.c")

b.attach_kprobe(event="tcp_v4_connect", fn_name="tcpconnect")

print("Ready")

try:
  b.trace_print()
except KeyboardInterrupt:
  print("\n unloading")

exit()
