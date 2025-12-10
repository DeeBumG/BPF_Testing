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
    Format: (dest_ip, prefix_len, out_interface, next_hop_mac)
    """

    routes = []

    # Configure which interface to use for routing
    DEV_NAME = "enp175s0f1"  # Change to enp175s0f0 to redirect to f0

    if DEV_NAME == "enp175s0f0":
        NEXT_HOP_MAC = "e8:ea:6a:2a:c3:7a"  # Next hop for f0
        IFINDEX = 4  # ifindex for f0
    else:  # enp175s0f1
        NEXT_HOP_MAC = "e8:ea:6a:2a:c3:7b"  # Next hop for f1
        IFINDEX = 5  # ifindex for f1

    counter = 0

    with open("routeviews-rv2-20230211-1200.pfx2as") as file:
        for line in file:
            if counter < 45465 or counter > 48788:
                routes.append((line.split()[0], int(line.split()[1]), DEV_NAME, NEXT_HOP_MAC))
            counter += 1

    routes.append(("28.0.0.0", 8, DEV_NAME, NEXT_HOP_MAC))

    for ip, prefix_len, out_interface, next_hop_mac_str in routes:
        try:
            smac = get_interface_mac(out_interface)
            dmac = mac_str_to_bytes(next_hop_mac_str)

        except Exception as e:
            print(f"Warning: Could not configure route for {ip}/{prefix_len}: {e}")
            continue

        key = trie_map.Key()
        key.prefixlen = ct.c_uint32(prefix_len)
        key.addr = ct.c_uint32(ip_to_int(ip))

        leaf = trie_map.Leaf()
        leaf.ifindex = ct.c_uint32(IFINDEX)

        for i in range(6):
            leaf.dmac[i] = dmac[i]
            leaf.smac[i] = smac[i]

        trie_map[key] = leaf

def main():
    try:
        route_trie = b["route_trie"]
    except KeyError as e:
        print(f"Error: Could not find route_trie map: {e}")
        return

    print("Populating routing table...")
    populate_route_table(route_trie)

    fn = b.load_func("xdp_main", BPF.XDP)


    interface_rx = "enp175s0f1"  # Interface receiving packets
    interface_tx = "enp175s0f0"  # Other interface (also receives a little traffic for some reason)

    attached_interfaces = []

    try:
        b.attach_xdp(interface_rx, fn, 0)
        attached_interfaces.append(interface_rx)
        print(f"XDP program attached to {interface_rx} (RX interface)")

        b.attach_xdp(interface_tx, fn, 0)
        attached_interfaces.append(interface_tx)
        print(f"XDP program attached to {interface_tx} (TX interface)")

        print("\nInterface enp175s0f1 configured for XDP redirect")
        print("Press Ctrl+C to exit...")
        print("=" * 60)
        b.trace_print()

    except KeyboardInterrupt:
        print("\nDetaching XDP programs...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        for iface in attached_interfaces:
            try:
                b.remove_xdp(iface, 0)
                print(f"Detached XDP from {iface}")
            except Exception as e:
                print(f"Error detaching from {iface}: {e}")
        print("Done.")

if __name__ == "__main__":
    main()
