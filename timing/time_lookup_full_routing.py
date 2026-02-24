#!/usr/bin/env python3
from bcc import BPF
import time

KERNEL_FUNCTION = "bpf_map_lookup_elem"

BPF_PROGRAM = r"""
#include <linux/ptrace.h>

BPF_HASH(start, u32, u64, 10240);   /* tid -> entry timestamp (ns)        */
BPF_PERCPU_ARRAY(total_ns,    u64, 1);  /* per-cpu cumulative ns          */
BPF_PERCPU_ARRAY(total_calls, u64, 1);  /* per-cpu cumulative call count  */

int kprobe__bpf_map_lookup_elem(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts  = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

int kretprobe__bpf_map_lookup_elem(struct pt_regs *ctx)
{
    u32 tid  = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&tid);
    if (!tsp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    int zero = 0;
    u64 *ns = total_ns.lookup(&zero);
    if (ns) __sync_fetch_and_add(ns, delta);

    u64 *calls = total_calls.lookup(&zero);
    if (calls) __sync_fetch_and_add(calls, 1);

    return 0;
}
"""

b = BPF(text=BPF_PROGRAM)
print(f"Tracing {KERNEL_FUNCTION}... Ctrl-C to stop.\n")

try:
    while True:
        time.sleep(3)

        calls = sum(b["total_calls"][0])
        ns    = sum(b["total_ns"][0])

        if calls:
            print(f"calls={calls}  avg={ns/calls:.1f} ns")
        else:
            print("no calls yet")

except KeyboardInterrupt:
    print("\nDone.")
