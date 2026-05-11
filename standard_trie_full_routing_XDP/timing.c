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

/* Per-CPU lookup timing counters */
BPF_PERCPU_ARRAY(lookup_ns,    u64, 1);
BPF_PERCPU_ARRAY(lookup_calls, u64, 1);

int xdp_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

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
        .addr      = ip->daddr,
    };

    /* --- time the LPM lookup --- */
    u64 t0 = bpf_ktime_get_ns();
    struct route_info *route = route_trie.lookup(&key);
    u64 dt = bpf_ktime_get_ns() - t0;

    int zero = 0;
    u64 *ns = lookup_ns.lookup(&zero);
    u64 *cn = lookup_calls.lookup(&zero);
    if (ns) *ns += dt;     /* per-CPU array: no atomics needed */
    if (cn) *cn += 1;
    /* --------------------------- */

    if (route) {
        memcpy(eth->h_dest,   route->dmac, ETH_ALEN);
        memcpy(eth->h_source, route->smac, ETH_ALEN);
        return bpf_redirect(route->ifindex, 0);
    }

    bpf_trace_printk("No route for dst=%x\n", ip->daddr);
    return XDP_PASS;
}
