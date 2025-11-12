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

BPF_LPM_TRIE(route_trie, struct lpm_key, struct route_info, 1024);

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

    // Lookup in custom routing table
    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr
    };

    struct route_info *route = route_trie.lookup(&key);

    if (route) {
        bpf_trace_printk("Route found for dst=%x\n", ip->daddr);
        memcpy(eth->h_dest, route->dmac, ETH_ALEN);   // Next-hop MAC
        memcpy(eth->h_source, route->smac, ETH_ALEN); // Outgoing interface MAC
        bpf_trace_printk("Redirecting to interface %u\n", route->ifindex);
        bpf_redirect(route->ifindex, 0);
        return XDP_REDIRECT;
    }

    bpf_trace_printk("No route for dst=%x\n", ip->daddr);
    return XDP_PASS;
}
