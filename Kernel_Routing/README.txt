standard_trie_kernel_routing_XDP.py
-XDP program that uses the kernel's FIB for lookups (no timing overhead, fastest)

standard_trie_kernel_routing_XDP_timing.py
-same as above, with timing implemented

no_xdp_timing.py
-timing program for measuting each lookup on a raw linux kernel with no XDP running
-Run this when no other XDP program is running to measure baseline kernel performance

