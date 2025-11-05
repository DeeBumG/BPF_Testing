#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct route_info {
    __u32 ifindex;  // Output interface index for forwarding
};

BPF_LPM_TRIE(route_trie, struct lpm_key, struct route_info, 1024);

int xdp_main(struct xdp_md *ctx) {
    // Cast the offsets to actual pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    // Bounds check
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    
    // Another bounds check
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Create lookup key with destination IP
    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr
    };

    struct route_info *route = route_trie.lookup(&key);

    if (route) {
        bpf_trace_printk("Route match: dst=%u redirect_interface=%u\n", (uint32_t)(ip->daddr), route->ifindex);
        return (bpf_redirect(route->ifindex, 0));
        //if (bpf_redirect(route->ifindex, 0) == XDP_REDIRECT){
        //    bpf_trace_printk("Redirected on interface: %u \n", route->ifindex);
        //    return XDP_REDIRECT;
        //};
    } else {
        bpf_trace_printk("No route for: dst=%x\n", ip->daddr);
    }

    return XDP_PASS;
}
