from bcc import BPF
import sys
import ctypes

device = "ens33"

# Load BPF program from file
b = BPF(src_file="xdp_drop_icmp.c", cflags=["-w"])
fn = b.load_func("xdp_prog", BPF.XDP)

# Attach to device
b.attach_xdp(device, fn, 0)

print(f"XDP program loaded on {device}. Ctrl+C to exit.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nRemoving XDP program...")
    b.remove_xdp(device, 0)
