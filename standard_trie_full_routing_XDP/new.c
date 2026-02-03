#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct route_info {
    __u32 ifindex;
    __u8 dmac[ETH_ALEN];  // Next-hop MAC (destination)
    __u8 smac[ETH_ALEN];  // Outgoing interface MAC (source)
};

BPF_LPM_TRIE(route_trie, struct lpm_key, struct route_info, 1000000);

int xdp_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr
    };

    struct route_info *route = route_trie.lookup(&key);

    if (route) {
        // **FIX 1: Prevent U-turn forwarding**
        // Never redirect packet back out the interface it arrived on
        if (route->ifindex == ctx->ingress_ifindex) {
            // This packet is either:
            // - Destined for this interface itself (local delivery)
            // - A routing loop/misconfiguration
            // Let the kernel handle it via XDP_PASS
            return XDP_PASS;
        }

        // **FIX 2: TTL check (standard forwarding requirement)**
        // Decrement and check TTL to prevent routing loops
        if (ip->ttl <= 1) {
            // TTL expired - let kernel generate ICMP Time Exceeded
            return XDP_PASS;
        }

        // Decrement TTL
        ip->ttl--;
        
        // Recalculate IP checksum for TTL change
        // Using incremental checksum update (RFC 1624)
        __u32 csum = ip->check;
        csum += htons(0x0100);  // Add 1 to TTL field
        ip->check = csum + ((csum >= 0xFFFF) ? 1 : 0);  // Add carry

        // Rewrite L2 headers and redirect
        memcpy(eth->h_dest, route->dmac, ETH_ALEN);   // Next-hop MAC
        memcpy(eth->h_source, route->smac, ETH_ALEN); // Outgoing interface MAC
        
        return bpf_redirect(route->ifindex, 0);
    }

    // No route found - pass to kernel for handling (ICMP unreachable, etc.)
    return XDP_PASS;
}
