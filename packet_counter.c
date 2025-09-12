#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>

#define IPPROTO_ICMP 1

// Define the per-CPU array map
//1 bucket, 64 bit integer, array name pkt_counter
BPF_PERCPU_ARRAY(pkt_counter, u64, 2);

int packet_watch(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    //if (ip->protocol == IPPROTO_ICMP) {
    //    bpf_trace_printk("ICMP packet\\n");
    //    return XDP_PASS;
    //}

    u32 total_key = 0;
    u64 *total_counter;

    u32 ICMP_key = 1;
    u64 *ICMP_counter;

    total_counter = pkt_counter.lookup(&total_key);
    if (total_counter) {
        (*total_counter)++;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        ICMP_counter = pkt_counter.lookup(&ICMP_key);
        if (ICMP_counter) {
          (*ICMP_counter)++;
      }
        return XDP_PASS;
    }


    return XDP_PASS;
}

int count_packets(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *counter;
    
    counter = pkt_counter.lookup(&key);
    if (counter) {
        (*counter)++;
    }
    
    // allows the packet to continue normally
    return XDP_PASS;
}
