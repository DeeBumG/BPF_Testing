#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import ctypes as ct
import fcntl

b = BPF(src_file="standard_trie_full_routing_XDP.c", debug=0)

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
    routes = []
    DEV_NAME = "enp175s0f0np0" #change to enp175s0f1np1 to redirect to f1
    if DEV_NAME == "enp175s0f0np0":
        NEXT_HOP_MAC = "e8:ea:6a:2a:c3:7a"
        IFINDEX = 4
    else:
        NEXT_HOP_MAC = "e8:ea:6a:2a:c3:7b"
        IFINDEX = 5

    counter = 0
    with open("routeviews-rv2-20230211-1200.pfx2as") as file:
        for line in file:
            if counter < 45465 or counter > 48788:
                routes.append((line.split()[0], int(line.split()[1]),
                               DEV_NAME, NEXT_HOP_MAC))
            counter += 1
    routes.append(("28.0.0.0", 8, DEV_NAME, NEXT_HOP_MAC))

    # Cache MACs once — they don't change per route.
    mac_cache = {}
    def get_macs(ifname, nh_mac_str):
        if ifname not in mac_cache:
            mac_cache[ifname] = (get_interface_mac(ifname),
                                 mac_str_to_bytes(nh_mac_str))
        return mac_cache[ifname]

    # Build exactly-sized arrays so len() == number of valid routes.
    KeyT  = trie_map.Key
    LeafT = trie_map.Leaf

    # (do MAC lookups, filter, collect into a Python list of (k_fields, l_fields) first)
    prepared = []
    mac_cache = {}
    for ip, plen, ifname, nh_mac_str in routes:
        try:
            if ifname not in mac_cache:
                mac_cache[ifname] = (get_interface_mac(ifname),
                                    mac_str_to_bytes(nh_mac_str))
            smac, dmac = mac_cache[ifname]
        except Exception as e:
            print(f"Warning: skip {ip}/{plen}: {e}")
            continue
        prepared.append((plen, ip_to_int(ip), smac, dmac))

    n = len(prepared)
    keys   = (KeyT  * n)()
    leaves = (LeafT * n)()
    for i, (plen, addr, smac, dmac) in enumerate(prepared):
        keys[i].prefixlen = ct.c_uint32(plen)
        keys[i].addr      = ct.c_uint32(addr)
        leaves[i].ifindex = ct.c_uint32(IFINDEX)
        for j in range(6):
            leaves[i].dmac[j] = dmac[j]
            leaves[i].smac[j] = smac[j]

    trie_map.items_update_batch(keys, leaves)

def main():
    try:
        route_trie = b["route_trie"]
    except KeyError as e:
        print(f"Error: Could not find route_trie map: {e}")
        return

    print("Populating routing table...")
    populate_route_table(route_trie)

    fn = b.load_func("xdp_main", BPF.XDP)


    interface1 = "enp175s0f1np1"
    interface0 = "enp175s0f0np0"

    try:
        b.attach_xdp(interface1, fn, 0)
        print(f"XDP program attached to {interface1} (RX interface)")

        b.attach_xdp(interface0, fn, 0)
        print(f"XDP program attached to {interface0} (TX interface)")

        print("\nInterfaces configured for XDP redirect f1 -> f0")
        print("Press Ctrl+C to exit...")
        print("=" * 60)
        b.trace_print()

    except KeyboardInterrupt:
        print("\nDetaching XDP programs...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            b.remove_xdp(interface1, 0)
            print(f"Detached XDP from {interface0}")
            b.remove_xdp(interface0, 0)
            print(f"Detached XDP from {interface0}")
        except Exception as e:
            print(f"Error detaching from interface: {e}")
        print("Done.")

if __name__ == "__main__":
    main()
