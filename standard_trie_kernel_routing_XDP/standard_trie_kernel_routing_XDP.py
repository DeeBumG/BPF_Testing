#!/usr/bin/env python3
from bcc import BPF
import socket
import struct

b = BPF(src_file="./standard_trie_kernel_routing_XDP.c")

def main():

    fn = b.load_func("xdp_main", BPF.XDP)
    
    interface1 = "enp175s0f1" 
    interface0 = "enp175s0f0"

    try:
        b.attach_xdp(interface1, fn, 0)
        print(f"\nXDP program attached to {interface1}")
        b.attach_xdp(interface0, fn, 0)
        print(f"\nXDP program attached to {interface0}")
        print("Press Ctrl+C to exit...")
        print("=" * 60)
        b.trace_print()
    except KeyboardInterrupt:
        print("\nDetaching XDP programs...")
    finally:
        b.remove_xdp(interface1, 0)
        b.remove_xdp(interface0, 0)
        print("Done.")

if __name__ == "__main__":
    main()
