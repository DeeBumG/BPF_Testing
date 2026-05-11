#!/usr/bin/env python3
from bcc import BPF
import time

b = BPF(src_file="./timing.c")

def main():
    fn = b.load_func("xdp_main", BPF.XDP)

    interface1 = "enp175s0f1np1"
    interface0 = "enp175s0f0np0"

    try:
        b.attach_xdp(interface1, fn, 0)
        print(f"\nXDP program attached to {interface1}")
        b.attach_xdp(interface0, fn, 0)
        print(f"\nXDP program attached to {interface0}")

        print("Sampling FIB lookup timing every 3s. Press Ctrl+C to exit.")
        print("=" * 78)

        lookup_ns    = b["lookup_ns"]
        lookup_calls = b["lookup_calls"]

        prev_ns    = 0
        prev_calls = 0

        while True:
            time.sleep(3)

            cur_ns    = sum(lookup_ns[0])
            cur_calls = sum(lookup_calls[0])

            d_ns    = cur_ns    - prev_ns
            d_calls = cur_calls - prev_calls
            prev_ns, prev_calls = cur_ns, cur_calls

            if d_calls:
                print(f"interval: calls={d_calls:>10}  avg={d_ns/d_calls:7.1f} ns   "
                      f"cumulative: calls={cur_calls:>12}  avg={cur_ns/cur_calls:7.1f} ns")
            else:
                print("no lookups this interval")

    except KeyboardInterrupt:
        print("\nDetaching XDP programs...")
    finally:
        b.remove_xdp(interface1, 0)
        b.remove_xdp(interface0, 0)
        print("Done.")

if __name__ == "__main__":
    main()
