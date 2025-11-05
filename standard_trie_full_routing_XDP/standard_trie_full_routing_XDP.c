#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct route_info {
    __u32 ifindex;
};

// Define the LPM trie map
BPF_TABLE("lpm_trie", struct lpm_key, struct route_info, route_trie, 1024);

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
        bpf_trace_printk("Route match: dst=%x redirect_interface=%u\\n", 
                         ip->daddr, route->ifindex);
        return bpf_redirect(route->ifindex, 0);
    } else {
        bpf_trace_printk("No route for: dst=%x\\n", ip->daddr);
    }

    return XDP_PASS;
}
