#!/usr/bin/env python3
"""
Plot FIB lookup timing across 4 implementations, averaging 3 trials each.

Expects 12 files in the working directory matching:
    full_poptrie_kernel_trial_{1,2,3}.txt
    full_standard_kernel_trial_{1,2,3}.txt
    kernel_XDP_trial_{1,2,3}.txt
    raw_kernel_trial_{1,2,3}.txt

Parses lines of the form:
    interval: calls=N  avg=X.X ns   cumulative: calls=M  avg=Y.Y ns

For each implementation, the per-interval averages from the 3 trials are
averaged together. Lines saying "no lookups this interval" are dropped (they
are warm-up / tear-down windows where TRex isn't sending). The result is a
single line plot of interval-averaged lookup time vs. elapsed test time.

Usage:
    cd ~/BPF_Testing/trials_m1000
    python3 plot_lookup_timing.py             # writes lookup_timing_comparison.png
    python3 plot_lookup_timing.py --show      # also pop up a window
"""

import argparse
import glob
import re
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Capture: interval calls, interval avg ns, cumulative calls, cumulative avg ns
INTERVAL_RE = re.compile(
    r"interval:\s+calls=\s*(\d+)\s+avg=\s*([\d.]+)\s+ns"
    r"\s+cumulative:\s+calls=\s*(\d+)\s+avg=\s*([\d.]+)\s+ns"
)

SAMPLE_PERIOD_S = 3  # the scripts sample every 3 seconds

# prefix -> (legend label, line color)
DATASETS = [
    ("full_poptrie_kernel",  "Full Internal BPF XDP Poptrie Kernel",         "#1f77b4"),
    ("full_standard_kernel", "Full Internal BPF XDP Standard Kernel)","#2ca02c"),
    ("kernel_XDP",           "BPF XDP Kernel FIB Lookup",              "#ff7f0e"),
    ("raw_kernel",           "Raw Kernel FIB Lookup",        "#d62728"),
]


def parse_trial(path):
    """Return two parallel lists: per-interval avg ns, and final cumulative avg ns."""
    intervals = []
    final_cum = None
    with open(path) as f:
        for line in f:
            m = INTERVAL_RE.search(line)
            if m:
                intervals.append(float(m.group(2)))
                final_cum = float(m.group(4))
    return intervals, final_cum


def average_trials(prefix, directory):
    paths = sorted(glob.glob(str(Path(directory) / f"{prefix}_trial_*.txt")))
    if not paths:
        return None, None, []
    trials, cums = [], []
    for p in paths:
        ivals, cum = parse_trial(p)
        if not ivals:
            print(f"warning: no interval lines parsed from {p}", file=sys.stderr)
            continue
        trials.append(ivals)
        if cum is not None:
            cums.append(cum)
    if not trials:
        return None, None, paths
    # truncate to the shortest trial so the elementwise mean is well-defined
    n = min(len(t) for t in trials)
    arr = np.array([t[:n] for t in trials])
    return arr.mean(axis=0), float(np.mean(cums)) if cums else None, paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".", help="directory containing trial files")
    ap.add_argument("--out", default="lookup_timing_comparison.png",
                    help="output image path")
    ap.add_argument("--show", action="store_true", help="display interactively")
    ap.add_argument("--logy", action="store_true",
                    help="use log scale on y-axis (helps when ranges differ a lot)")
    args = ap.parse_args()

    fig, ax = plt.subplots(figsize=(11, 6.2))

    summary_rows = []
    for prefix, label, color in DATASETS:
        mean_curve, mean_cum, paths = average_trials(prefix, args.dir)
        if mean_curve is None:
            print(f"skipping {prefix}: no files matched in {args.dir}", file=sys.stderr)
            continue
        x = np.arange(len(mean_curve)) * SAMPLE_PERIOD_S
        ax.plot(x, mean_curve, marker="o", markersize=3.5, linewidth=1.6,
                color=color, label=f"{label}  (mean cum: {mean_cum:.1f} ns)")
        summary_rows.append((label, mean_cum, len(paths), len(mean_curve)))

    ax.set_xlabel("Elapsed test time (s)")
    ax.set_ylabel("Mean lookup time per 3 s interval (ns)")
    ax.set_title("FIB lookup latency: 4 implementations\n"
                 "(per-interval mean, averaged across 3 trials each)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best", framealpha=0.92)
    if args.logy:
        ax.set_yscale("log")
    fig.tight_layout()
    fig.savefig(args.out, dpi=140)
    print(f"wrote {args.out}")

    print("\nSummary (mean of final-cumulative averages across trials):")
    print(f"  {'implementation':<42} {'cum avg (ns)':>14} {'trials':>8}")
    for label, cum, ntrials, nints in summary_rows:
        print(f"  {label:<42} {cum:>14.1f} {ntrials:>8d}")

    if args.show:
        plt.show()


if __name__ == "__main__":
    main()
