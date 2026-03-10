from bcc import BPF
import ctypes as ct
import socket
import struct

b = BPF(src_file="lpm_test.c")
trie = b["route_trie"]

class Key(ct.Structure):
    _fields_ = [
        ("prefixlen", ct.c_uint32),
        ("addr", ct.c_uint32),
    ]

class Leaf(ct.Structure):
    _fields_ = [("value", ct.c_uint32)]

def ip_to_int(ip):
    return struct.unpack("=I", socket.inet_aton(ip))[0]

k = Key(24, ip_to_int("192.168.1.0"))
v = Leaf(123)

trie[k] = v

print("Inserted route successfully")
