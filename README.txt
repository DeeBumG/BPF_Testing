BPF_Testing

XDP programs for research to find faster routing methods for the Linux kernel.

lpm_trie.c is a drop-in poptrie implementation of the linux kernel's lpm_trie.c. It is only functional for ipv4. 

XDP_Internal_Routing contains programs that utilize a FIB within XDP, requiring no interaction with the kernel's FIB.

Kernel_Routing contains XDP programs that query the kernel's FIB for each lookup. 

In total, there are 2 main programs: 
    Kernel_Routing/standard_trie_kernel_routing_XDP.py - Uses XDP with the kernel's FIB

    XDP_Internal_Routing/redirect_to_f0_batch.py - sets up XDP program with it's own internal FIB

The other 2 approaches are:
    A baseline using no XDP programs (kernel's FIB alone)   
    XDP_Internal_Routing/redirect_to_f0_batch.py run after recompiling the kernel with the updates lpm_trie.c poptrie implementation

There are timing programs throughout that are slightly modified versions of the above to time each lookup performed. 

trials_m1000 contains test data of the 4 implementations only considering timing lookups. 

Claude was used to do most of the heavy lifting for programming implementation.
