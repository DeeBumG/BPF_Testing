#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import ctypes as ct

# Load with debug flag to see what's happening
b = BPF(src_file="./standard_trie_full_routing_XDP.c", debug=0)

def ip_to_int(ip_str):
    """Convert IP string to integer (network byte order)"""
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]

def get_interface_index(interface_name):
    """Get the interface index for a given interface name"""
    import fcntl
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('16si', interface_name.encode(), 0)
        res = fcntl.ioctl(sock.fileno(), 0x8933, ifreq)
        index = struct.unpack('16si', res)[1]
        return index
    finally:
        sock.close()

def populate_route_table(trie_map):
    routes = [
        ("0.0.0.0", 0, "enp175s0f1"),
        #("192.168.255.0", 24, "enp175s0f0"),
        #("251.0.0.224", 27, "lo"),
    ]
    
    for ip, prefix_len, out_interface in routes:
        try:
            ifindex = get_interface_index(out_interface)
        except Exception as e:
            print(f"Warning: Could not get index for {out_interface}: {e}")
            continue
        
        # Create key structure
        key = trie_map.Key()
        key.prefixlen = ct.c_uint32(prefix_len)
        key.addr = ct.c_uint32(ip_to_int(ip))
        
        # Create value structure
        leaf = trie_map.Leaf()
        leaf.ifindex = ct.c_uint32(ifindex)
        
        trie_map[key] = leaf
        print(f"Added route: {ip}/{prefix_len} -> {out_interface} (ifindex {ifindex})")

def main():
    try:
        route_trie = b["route_trie"]
    except KeyError as e:
        print(f"Error: Could not find route_trie map: {e}")
        return
    
    print("Populating routing table...")
    populate_route_table(route_trie)
    
    fn = b.load_func("xdp_main", BPF.XDP)
    
    interface = "enp175s0f1"

    try:
        b.attach_xdp(interface, fn, 0)
        print(f"\nXDP program attached to {interface}")
        print("Press Ctrl+C to exit...")
        print("=" * 60)
        b.trace_print()
    except KeyboardInterrupt:
        print("\nDetaching XDP program...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        b.remove_xdp(interface, 0)
        print("Done.")

if __name__ == "__main__":
    main()
