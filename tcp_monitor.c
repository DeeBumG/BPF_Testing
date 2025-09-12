#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/tcp.h>

int tcpconnect(struct pt_regs *ctx, struct sock *sk) {
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = ntohs(dport);

    bpf_trace_printk("tcp connect to port %d\n", dport);
    return 0;
}
