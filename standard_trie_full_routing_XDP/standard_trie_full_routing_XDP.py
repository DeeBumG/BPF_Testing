#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import ctypes as ct
import fcntl

b = BPF(src_file="./standard_trie_full_routing_XDP.c", debug=0)

def ip_to_int(ip_str):
    """Convert IP string to integer (network byte order)"""
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]

def get_interface_index(interface_name):
    """Get the interface index for a given interface name"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('16si', interface_name.encode(), 0)
        res = fcntl.ioctl(sock.fileno(), 0x8933, ifreq)
        index = struct.unpack('16si', res)[1]
        return index
    finally:
        sock.close()

def get_interface_mac(interface_name):
    """Get the MAC address for a given interface"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('256s', interface_name.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), 0x8927, ifreq)
        mac_bytes = res[18:24]
        return mac_bytes
    finally:
        sock.close()

def mac_str_to_bytes(mac_str):
    """Convert MAC string (e.g., 'aa:bb:cc:dd:ee:ff') to bytes"""
    return bytes.fromhex(mac_str.replace(':', ''))

def populate_route_table(trie_map):
    """
    Populate routing table with routes
    Format: (dest_ip, prefix_len, out_interface, next_hop_mac
    """
    routes = [
        ("172.16.1.0", 24, "enp175s0f1", "e8:ea:6a:2a:c3:7b"),
    ]

    for ip, prefix_len, out_interface, next_hop_mac_str in routes:
        try:
            ifindex = get_interface_index(out_interface)
            smac = get_interface_mac(out_interface)
            dmac = mac_str_to_bytes(next_hop_mac_str)

        except Exception as e:
            print(f"Warning: Could not configure route for {ip}/{prefix_len}: {e}")
            continue

        key = trie_map.Key()
        key.prefixlen = ct.c_uint32(prefix_len)
        key.addr = ct.c_uint32(ip_to_int(ip))

        leaf = trie_map.Leaf()
        leaf.ifindex = ct.c_uint32(ifindex)

        for i in range(6):
            leaf.dmac[i] = dmac[i]
            leaf.smac[i] = smac[i]

        trie_map[key] = leaf

        print(f"Added route: {ip}/{prefix_len} -> {out_interface} (ifindex {ifindex})")
        print(f"  Source MAC (interface): {':'.join(f'{b:02x}' for b in smac)}")
        print(f"  Dest MAC (next-hop):    {next_hop_mac_str}")

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
