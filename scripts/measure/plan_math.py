#!/usr/bin/env python3
"""Statistical derivations behind MASTER_PLAN_v3_DETAILED.md §0, §5.3, §6.
Owner: CLAUDE. 2026-09-09. Pure stdlib; re-run to reproduce every number in the plan.
Usage: python3 scripts/measure/plan_math.py
"""
import math
from statistics import NormalDist

Z95 = 1.959963984540054
N = NormalDist()


def wilson(k, n, z=Z95):
    """Wilson score interval for a binomial proportion (works at p=0 or 1)."""
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def n_for_mean(sigma, margin, z=Z95):
    """Sample size so that the 95% CI half-width of a mean is <= margin."""
    return math.ceil((z * sigma / margin) ** 2)


def n_two_sample(delta, sigma, alpha=0.05, power=0.80):
    """Per-group n for a two-sided two-sample test (normal approximation)."""
    z = N.inv_cdf(1 - alpha / 2) + N.inv_cdf(power)
    return math.ceil(2 * (z * sigma / delta) ** 2)


def poisson_upper_zero(hours, alpha=0.05):
    """Exact 95% upper bound on a Poisson rate when 0 events observed in `hours`."""
    return -math.log(alpha) / hours


def main():
    print("A. Detection rate — Wilson 95% CI at k=n (all detected)")
    for n in (5, 10, 20, 30, 50):
        lo, _ = wilson(n, n)
        print(f"   n={n:2d}: lower bound {lo*100:5.1f}%   rule-of-three miss bound {300/n:4.1f}%")
    print("   -> plan: n=20 for standard UCs (>=83.9%), n=30 for AR UCs (>=88.6%)")

    print("\nB. n for a mean latency with margin E=±1 s")
    for s in (1, 2, 3, 5):
        print(f"   sigma={s}s -> n={n_for_mean(s, 1.0)}")
    print("   -> sigma unknown until PILOT (n=5); floor n=20")

    print("\nC. Two-sample per-group n (H4: hardened AR vs official)")
    for d, s in ((1, 1), (1, 2), (0.5, 1)):
        print(f"   delta={d}s sigma={s}s -> n/group={n_two_sample(d, s)}")
    print("   -> plan: 30+30 detects delta ~= 0.75 sigma")

    print("\nD. Baseline FP/hour — Poisson exact 95% upper bound at 0 FP")
    for h in (1, 2, 3, 4, 6, 8):
        print(f"   {h}h -> < {poisson_upper_zero(h):.2f} FP/h")
    print("   -> plan: >= 6 h per OS to claim FP/h < 0.5")

    print("\nE. VirusTotal public API budget (4/min, 500/day)")
    lookups = 30 * 2
    print(f"   UC-03 MEASURED = 30 trials x 2 OS = {lookups} lookups")
    print(f"   at 90 s spacing = {lookups*90/60:.0f} min; daily cap not binding")

    print("\nF. Trial budget")
    std = 8 * 20 * 1.5
    ar = 2 * 30 * 1.5
    m0 = 10
    total = std + ar + m0
    print(f"   standard {std:.0f} + AR {ar:.0f} + M0 {m0} = {total:.0f} measured trials")
    print(f"   + 40 PILOT; at 2 min each = {total*2/60:.1f} h + 12 h baseline")

    print("\nG. Memory budget (Cloud Computer 16 GB)")
    vms = {"wazuh-server": 4, "kali1": 2, "win1": 4, "mikrotik-chr": 0.25}
    used = sum(vms.values()) + 2  # +2 GB host
    print(f"   VMs {sum(vms.values()):.2f} GB + host 2 GB = {used:.2f} GB; headroom {16-used:.2f} GB")


if __name__ == "__main__":
    main()
