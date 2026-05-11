#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import ctypes as ct
import fcntl

b = BPF(src_file="test.c", debug=0)

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

    print(f"[DEBUG] Egress device: {DEV_NAME} (ifindex={IFINDEX})")
    print(f"[DEBUG] Next-hop MAC:  {NEXT_HOP_MAC}")

    total_lines = 0
    skipped = 0
    with open("routeviews-rv2-20230211-1200.pfx2as") as file:
        for line in file:
            if total_lines < 45465 or total_lines > 48788:
                routes.append((line.split()[0], int(line.split()[1]),
                               DEV_NAME, NEXT_HOP_MAC))
            else:
                skipped += 1
            total_lines += 1
    routes.append(("28.0.0.0", 8, DEV_NAME, NEXT_HOP_MAC))

    print(f"[DEBUG] Read {total_lines} lines from pfx2as, skipped {skipped} in filter window")
    print(f"[DEBUG] Candidate routes (incl. manual 28.0.0.0/8): {len(routes)}")

    KeyT  = trie_map.Key
    LeafT = trie_map.Leaf

    prepared = []
    mac_cache = {}
    for ip, plen, ifname, nh_mac_str in routes:
        try:
            if ifname not in mac_cache:
                mac_cache[ifname] = (get_interface_mac(ifname),
                                    mac_str_to_bytes(nh_mac_str))
            smac, dmac = mac_cache[ifname]
        except Exception as e:
            print(f"[WARN] skip {ip}/{plen}: {e}")
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
    return n

def main():
    try:
        route_trie = b["route_trie"]
    except KeyError as e:
        print(f"Error: Could not find route_trie map: {e}")
        return

    print("=" * 60)
    print("Populating routing table...")
    print("=" * 60)
    n_loaded = populate_route_table(route_trie)
    print(f"[OK] Loaded {n_loaded} routes into LPM trie\n")

    fn = b.load_func("xdp_main", BPF.XDP)
    print("[DEBUG] XDP function 'xdp_main' loaded")

    interface1 = "enp175s0f1np1"
    interface0 = "enp175s0f0np0"

    idx0 = get_interface_index(interface0)
    idx1 = get_interface_index(interface1)
    print(f"[DEBUG] {interface0} ifindex = {idx0}")
    print(f"[DEBUG] {interface1} ifindex = {idx1}")

    try:
        b.attach_xdp(interface1, fn, 0)
        print(f"[OK] XDP attached to {interface1} (ifindex={idx1}) [RX]")

        b.attach_xdp(interface0, fn, 0)
        print(f"[OK] XDP attached to {interface0} (ifindex={idx0}) [TX]")

        print("\n" + "=" * 60)
        print("Interfaces configured for XDP redirect f1 -> f0")
        print("Streaming trace output (RX / TX redirect / no-route)...")
        print("Press Ctrl+C to exit")
        print("=" * 60)
        b.trace_print()

    except KeyboardInterrupt:
        print("\nDetaching XDP programs...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            b.remove_xdp(interface1, 0)
            print(f"Detached XDP from {interface1}")
            b.remove_xdp(interface0, 0)
            print(f"Detached XDP from {interface0}")
        except Exception as e:
            print(f"Error detaching from interface: {e}")
        print("Done.")

if __name__ == "__main__":
    main()
