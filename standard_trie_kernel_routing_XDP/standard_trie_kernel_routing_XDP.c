#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

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

    //initialize params for bpf_fib_lookup
    struct bpf_fib_lookup fib_params = {};

    //fill params for lookup using kernel routing table
    fib_params.family = AF_INET;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    //perform lookup from kernel routing table
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    
    bpf_trace_printk("Redirecting...\n");
    
    memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN); //setting nexthop mac
    
    //eth = fib_params.dmac; //setting nexthop mac

    // -------------------------------
    // testing - redirects to loopback
    // __u32 if_index = 1; // loopback

    //if (bpf_redirect(if_index, 0) == XDP_REDIRECT){
    //    bpf_trace_printk("Redirected on interface: %u \n", if_index);
    //    return XDP_REDIRECT;
    //};
    //end of testing
    //--------------------------------

    if (bpf_redirect(fib_params.ifindex, 0) == XDP_REDIRECT){
        bpf_trace_printk("Redirected on interface: %u \n", fib_params.ifindex);
        return XDP_REDIRECT;
    };

    bpf_trace_printk("LOOKUP / REDIRECT FAILURE!\n");
    bpf_trace_printk("Return Code: %d", rc);
    return XDP_PASS;
}
