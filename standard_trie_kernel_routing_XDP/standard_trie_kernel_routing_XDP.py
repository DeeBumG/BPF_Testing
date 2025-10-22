#!/usr/bin/env python3
from bcc import BPF
import socket
import struct

b = BPF(src_file="./standard_trie_kernel_routing_XDP.c")

def main():

    fn = b.load_func("xdp_main", BPF.XDP)
    
    interface = "ens33"

    try:
        b.attach_xdp(interface, fn, 0)
        print(f"\nXDP program attached to {interface}")
        print("Press Ctrl+C to exit...")
        print("=" * 60)
        b.trace_print()
    except KeyboardInterrupt:
        print("\nDetaching XDP program...")
    finally:
        b.remove_xdp(interface, 0)
        print("Done.")

if __name__ == "__main__":
    main()
