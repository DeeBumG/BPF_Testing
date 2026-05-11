#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* Per-CPU FIB lookup timing counters */
BPF_PERCPU_ARRAY(lookup_ns,    u64, 1);
BPF_PERCPU_ARRAY(lookup_calls, u64, 1);

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

    struct bpf_fib_lookup fib_params = {};

    fib_params.family   = AF_INET;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex  = ctx->ingress_ifindex;

    /* --- time the kernel FIB lookup --- */
    u64 t0 = bpf_ktime_get_ns();
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    u64 dt = bpf_ktime_get_ns() - t0;

    int zero = 0;
    u64 *ns = lookup_ns.lookup(&zero);
    u64 *cn = lookup_calls.lookup(&zero);
    if (ns) *ns += dt;     /* per-CPU array: no atomics needed */
    if (cn) *cn += 1;
    /* ---------------------------------- */

    memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);   // Set destination MAC (next hop)
    memcpy(eth->h_source, fib_params.smac, ETH_ALEN); // Set source MAC (outgoing interface)
    //bpf_trace_printk("Redirected on interface: %u \n", fib_params.ifindex);
    return (bpf_redirect(fib_params.ifindex, 0));

    bpf_trace_printk("LOOKUP / REDIRECT FAILURE!\n");
    bpf_trace_printk("Return Code: %d", rc);
    return XDP_PASS;
}
