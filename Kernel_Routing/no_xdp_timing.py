#!/usr/bin/env python3
from bcc import BPF
import time

BPF_PROGRAM = r"""
#include <linux/ptrace.h>

/* Per-CPU entry timestamp. Softirqs run with bottom-halves disabled,
 * so on a given CPU only one fib_table_lookup is "in flight" at a time
 * and a single-slot per-CPU array is sufficient (no need for a tid hash). */
BPF_PERCPU_ARRAY(start,        u64, 1);
BPF_PERCPU_ARRAY(lookup_ns,    u64, 1);
BPF_PERCPU_ARRAY(lookup_calls, u64, 1);

int kprobe__fib_table_lookup(struct pt_regs *ctx)
{
    int zero = 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&zero, &ts);
    return 0;
}

int kretprobe__fib_table_lookup(struct pt_regs *ctx)
{
    int zero = 0;
    u64 *tsp = start.lookup(&zero);
    if (!tsp || *tsp == 0)
        return 0;

    u64 dt = bpf_ktime_get_ns() - *tsp;
    *tsp = 0;   /* mark consumed so a stray return doesn't double-count */

    u64 *ns = lookup_ns.lookup(&zero);
    u64 *cn = lookup_calls.lookup(&zero);
    if (ns) *ns += dt;
    if (cn) *cn += 1;
    return 0;
}
"""

b = BPF(text=BPF_PROGRAM)

print("Tracing fib_table_lookup (kernel IPv4 LPM trie)... Ctrl-C to stop.")
print("Sampling every 3s.")
print("=" * 78)

lookup_ns    = b["lookup_ns"]
lookup_calls = b["lookup_calls"]

prev_ns    = 0
prev_calls = 0

try:
    while True:
        time.sleep(3)

        cur_ns    = sum(lookup_ns[0])
        cur_calls = sum(lookup_calls[0])

        d_ns    = cur_ns    - prev_ns
        d_calls = cur_calls - prev_calls
        prev_ns, prev_calls = cur_ns, cur_calls

        if d_calls:
            print(f"interval: calls={d_calls:>10}  avg={d_ns/d_calls:7.1f} ns   "
                  f"cumulative: calls={cur_calls:>12}  avg={cur_ns/cur_calls:7.1f} ns")
        else:
            print("no lookups this interval")

except KeyboardInterrupt:
    print("\nDone.")
