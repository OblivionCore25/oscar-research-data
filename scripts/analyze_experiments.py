#!/usr/bin/env python3
"""
OSCAR — Experiment Analysis Script
===================================
Produces all quantitative results for §5 (Evaluation) of the ICSE paper.

RQ1: Ranking Effectiveness — cross-level vs single-level baselines
RQ2: Reachability Filtering — CVE false-positive reduction potential
RQ3: Formula Sensitivity  — stability across 4 formula parameterizations

Usage:
    python research/scripts/analyze_experiments.py

Outputs:
    research/data/rq1_results.csv
    research/data/rq2_results.csv
    research/data/rq3_results.csv
    research/data/experiment_summary.txt   (for direct paste into §5)
"""

import os
import sys
import csv
import math
import json
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_DIR = DATA_DIR  # co-locate with existing CSVs

# Auto-detect latest export files
def find_latest(prefix):
    """Find the latest CSV matching the prefix in DATA_DIR."""
    candidates = sorted(DATA_DIR.glob(f"{prefix}_*.csv"), reverse=True)
    if not candidates:
        print(f"ERROR: No {prefix}_*.csv found in {DATA_DIR}")
        sys.exit(1)
    return candidates[0]

CORPUS_FILE = find_latest("corpus_summary")
CROSS_LEVEL_FILE = find_latest("cross_level_results")
VULN_FILE = find_latest("vulnerability_results")
HOTSPOTS_FILE = find_latest("method_hotspots")
TEMPORAL_FILE = find_latest("temporal_profiles")


# ──────────────────────────────────────────────────────────────
# CSV Helpers
# ──────────────────────────────────────────────────────────────

def load_csv(path):
    """Load CSV as list of dicts."""
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def safe_float(val, default=0.0):
    """Convert to float, handling empty/None."""
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def safe_int(val, default=0):
    """Convert to int, handling empty/None."""
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


# ──────────────────────────────────────────────────────────────
# Load Data
# ──────────────────────────────────────────────────────────────

print("=" * 70)
print("OSCAR EXPERIMENT ANALYSIS")
print(f"Timestamp: {datetime.now().isoformat()}")
print("=" * 70)

print(f"\nLoading data from: {DATA_DIR}")
corpus = load_csv(CORPUS_FILE)
cross_level = load_csv(CROSS_LEVEL_FILE)
vulns = load_csv(VULN_FILE)
hotspots = load_csv(HOTSPOTS_FILE)
temporal = load_csv(TEMPORAL_FILE)

print(f"  corpus_summary:       {len(corpus)} packages")
print(f"  cross_level_results:  {len(cross_level)} method-risk entries")
print(f"  vulnerability_results:{len(vulns)} CVE records")
print(f"  method_hotspots:      {len(hotspots)} hotspot entries")
print(f"  temporal_profiles:    {len(temporal)} packages")


# ══════════════════════════════════════════════════════════════
# §5.2  CORPUS STATISTICS (Table 1)
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("§5.2 CORPUS STATISTICS")
print("=" * 70)

npm_pkgs = [p for p in corpus if p['ecosystem'] == 'npm']
pypi_pkgs = [p for p in corpus if p['ecosystem'] == 'pypi']

# Category breakdown
categories = Counter(p['category'] for p in corpus)

# Method counts
npm_methods = [safe_float(p['method_count']) for p in npm_pkgs if p['method_count']]
pypi_methods = [safe_float(p['method_count']) for p in pypi_pkgs if p['method_count']]
all_methods = npm_methods + pypi_methods

# Resolution rates
npm_rr = [safe_float(p['resolution_rate']) for p in npm_pkgs if p['resolution_rate']]
pypi_rr = [safe_float(p['resolution_rate']) for p in pypi_pkgs if p['resolution_rate']]

# LOC
npm_loc = [safe_float(p['total_loc']) for p in npm_pkgs if p['total_loc']]
pypi_loc = [safe_float(p['total_loc']) for p in pypi_pkgs if p['total_loc']]

# CVEs per ecosystem
npm_vulns = [v for v in vulns if v['root_ecosystem'] == 'npm']
pypi_vulns = [v for v in vulns if v['root_ecosystem'] == 'pypi']

# Unique CVEs
all_unique_cves = set(v['vuln_id'] for v in vulns)
npm_unique_cves = set(v['vuln_id'] for v in npm_vulns)
pypi_unique_cves = set(v['vuln_id'] for v in pypi_vulns)

# Global fan-in stats
fan_ins = [safe_float(p['global_fan_in']) for p in corpus if p['global_fan_in']]

def avg(lst):
    return sum(lst) / len(lst) if lst else 0

def median(lst):
    if not lst: return 0
    s = sorted(lst)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n//2 - 1] + s[n//2]) / 2

corpus_stats = {
    'total_packages': len(corpus),
    'npm_packages': len(npm_pkgs),
    'pypi_packages': len(pypi_pkgs),
    'categories': dict(categories),
    'npm_avg_methods': avg(npm_methods),
    'pypi_avg_methods': avg(pypi_methods),
    'all_avg_methods': avg(all_methods),
    'npm_avg_resolution_rate': avg(npm_rr),
    'pypi_avg_resolution_rate': avg(pypi_rr),
    'npm_avg_loc': avg(npm_loc),
    'pypi_avg_loc': avg(pypi_loc),
    'total_unique_cves': len(all_unique_cves),
    'npm_unique_cves': len(npm_unique_cves),
    'pypi_unique_cves': len(pypi_unique_cves),
    'max_fan_in': max(fan_ins) if fan_ins else 0,
    'median_fan_in': median(fan_ins),
    'avg_fan_in': avg(fan_ins),
}

print(f"\n  Packages:          {corpus_stats['total_packages']} ({corpus_stats['npm_packages']} npm, {corpus_stats['pypi_packages']} PyPI)")
print(f"  Categories:        {corpus_stats['categories']}")
print(f"  Avg methods (npm): {corpus_stats['npm_avg_methods']:.0f}")
print(f"  Avg methods (pypi):{corpus_stats['pypi_avg_methods']:.0f}")
print(f"  Avg res. rate npm: {corpus_stats['npm_avg_resolution_rate']:.1%}")
print(f"  Avg res. rate pypi:{corpus_stats['pypi_avg_resolution_rate']:.1%}")
print(f"  Avg LOC (npm):     {corpus_stats['npm_avg_loc']:.0f}")
print(f"  Avg LOC (pypi):    {corpus_stats['pypi_avg_loc']:.0f}")
print(f"  Unique CVEs:       {corpus_stats['total_unique_cves']} ({corpus_stats['npm_unique_cves']} npm, {corpus_stats['pypi_unique_cves']} PyPI)")
print(f"  Max fan-in:        {corpus_stats['max_fan_in']:,.0f}")
print(f"  Median fan-in:     {corpus_stats['median_fan_in']:,.0f}")


# ══════════════════════════════════════════════════════════════
# RQ1: RANKING EFFECTIVENESS
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("RQ1: RANKING EFFECTIVENESS")
print("Cross-level vs single-level approaches")
print("=" * 70)

# Strategy: for each root package with CVEs, we check whether the cross-level
# ranking places methods from *vulnerable dependencies* higher than the
# single-level alternatives (method-only composite risk, ecosystem-only fan-in).
#
# We compute Precision@K: "Of the top-K methods flagged, how many belong to
# dependencies that have known CVEs?"

# Build set of (root_package, affected_dep) pairs from vuln data
vuln_deps = defaultdict(set)
for v in vulns:
    vuln_deps[v['root_package']].add(v['affected_package'])

# Group cross-level results by root package
cl_by_root = defaultdict(list)
for row in cross_level:
    cl_by_root[row['root_package']].append(row)

# For each root package with vulns, compute Precision@K for three strategies
K_VALUES = [3, 5, 10]

rq1_results = []

for root_pkg, vuln_dep_set in vuln_deps.items():
    if root_pkg not in cl_by_root:
        continue
    
    methods = cl_by_root[root_pkg]
    if not methods:
        continue
    
    # Strategy 1: Cross-Level Risk (our approach)
    cl_sorted = sorted(methods, key=lambda m: safe_float(m['cross_level_risk']), reverse=True)
    
    # Strategy 2: Method-only (composite risk without fan-in scaling)
    method_sorted = sorted(methods, key=lambda m: safe_float(m['method_composite_risk']), reverse=True)
    
    # Strategy 3: Ecosystem-only (fan-in without method inspection)
    eco_sorted = sorted(methods, key=lambda m: safe_float(m['ecosystem_fan_in']), reverse=True)
    
    for K in K_VALUES:
        # Precision@K = |top-K methods from vulnerable deps| / K
        def precision_at_k(sorted_methods, k):
            top_k = sorted_methods[:k]
            hits = sum(1 for m in top_k if m['dependency_package'] in vuln_dep_set)
            return hits / k if k > 0 else 0
        
        p_cl = precision_at_k(cl_sorted, K)
        p_method = precision_at_k(method_sorted, K)
        p_eco = precision_at_k(eco_sorted, K)
        
        rq1_results.append({
            'root_package': root_pkg,
            'K': K,
            'precision_cross_level': round(p_cl, 4),
            'precision_method_only': round(p_method, 4),
            'precision_ecosystem_only': round(p_eco, 4),
            'n_vuln_deps': len(vuln_dep_set),
            'n_total_methods': len(methods),
        })

# Aggregate across all root packages
print(f"\n  Root packages with CVEs: {len(vuln_deps)}")
print(f"  Root packages with cross-level data + CVEs: {len(set(r['root_package'] for r in rq1_results))}")

print(f"\n  {'K':>3}  {'P@K (Cross-Level)':>20}  {'P@K (Method-Only)':>20}  {'P@K (Eco-Only)':>20}  {'Improvement':>12}")
print("  " + "-" * 80)

rq1_summary = {}
for K in K_VALUES:
    k_results = [r for r in rq1_results if r['K'] == K]
    if not k_results:
        continue
    
    avg_cl = avg([r['precision_cross_level'] for r in k_results])
    avg_method = avg([r['precision_method_only'] for r in k_results])
    avg_eco = avg([r['precision_ecosystem_only'] for r in k_results])
    
    # Improvement over best single-level baseline
    best_baseline = max(avg_method, avg_eco)
    improvement = ((avg_cl - best_baseline) / best_baseline * 100) if best_baseline > 0 else 0
    
    rq1_summary[K] = {
        'avg_precision_cross_level': round(avg_cl, 4),
        'avg_precision_method_only': round(avg_method, 4),
        'avg_precision_eco_only': round(avg_eco, 4),
        'improvement_pct': round(improvement, 1),
    }
    
    print(f"  {K:>3}  {avg_cl:>20.4f}  {avg_method:>20.4f}  {avg_eco:>20.4f}  {improvement:>+11.1f}%")

# nDCG computation
def dcg_at_k(relevance_scores, k):
    """Discounted Cumulative Gain at K."""
    dcg = 0.0
    for i, rel in enumerate(relevance_scores[:k]):
        dcg += rel / math.log2(i + 2)  # i+2 because positions are 1-indexed
    return dcg

def ndcg_at_k(predicted_relevance, ideal_relevance, k):
    """Normalized DCG: ratio of actual DCG to ideal DCG."""
    actual_dcg = dcg_at_k(predicted_relevance, k)
    ideal_dcg = dcg_at_k(sorted(ideal_relevance, reverse=True), k)
    return actual_dcg / ideal_dcg if ideal_dcg > 0 else 0

print(f"\n  nDCG Analysis:")
ndcg_results = {}

for K in K_VALUES:
    ndcgs_cl, ndcgs_method, ndcgs_eco = [], [], []
    
    for root_pkg, vuln_dep_set in vuln_deps.items():
        if root_pkg not in cl_by_root:
            continue
        methods = cl_by_root[root_pkg]
        if not methods:
            continue
        
        # Relevance: 1 if method is from a vulnerable dep, 0 otherwise
        cl_sorted = sorted(methods, key=lambda m: safe_float(m['cross_level_risk']), reverse=True)
        method_sorted = sorted(methods, key=lambda m: safe_float(m['method_composite_risk']), reverse=True)
        eco_sorted = sorted(methods, key=lambda m: safe_float(m['ecosystem_fan_in']), reverse=True)
        
        ideal_rel = [1 if m['dependency_package'] in vuln_dep_set else 0 for m in cl_sorted]
        
        cl_rel = [1 if m['dependency_package'] in vuln_dep_set else 0 for m in cl_sorted]
        method_rel = [1 if m['dependency_package'] in vuln_dep_set else 0 for m in method_sorted]
        eco_rel = [1 if m['dependency_package'] in vuln_dep_set else 0 for m in eco_sorted]
        
        ndcgs_cl.append(ndcg_at_k(cl_rel, ideal_rel, K))
        ndcgs_method.append(ndcg_at_k(method_rel, ideal_rel, K))
        ndcgs_eco.append(ndcg_at_k(eco_rel, ideal_rel, K))
    
    avg_ndcg_cl = avg(ndcgs_cl)
    avg_ndcg_method = avg(ndcgs_method)
    avg_ndcg_eco = avg(ndcgs_eco)
    
    ndcg_results[K] = {
        'ndcg_cross_level': round(avg_ndcg_cl, 4),
        'ndcg_method_only': round(avg_ndcg_method, 4),
        'ndcg_eco_only': round(avg_ndcg_eco, 4),
    }
    
    print(f"    nDCG@{K}: Cross-Level={avg_ndcg_cl:.4f}  Method-Only={avg_ndcg_method:.4f}  Eco-Only={avg_ndcg_eco:.4f}")


# ══════════════════════════════════════════════════════════════
# RQ1b: FUNCTION-LEVEL GROUND TRUTH (Fix 1)
# Uses mined CVE functions as precise ground truth instead of
# package-level CVE association.
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("RQ1b: FUNCTION-LEVEL PRECISION (using mined CVE functions)")
print("=" * 70)

# Load CVE patch mining data to build function-level ground truth
CVE_PATCH_FILE = DATA_DIR / "cve_patch_analysis.csv"
if CVE_PATCH_FILE.exists():
    cve_patches = load_csv(CVE_PATCH_FILE)

    # Build set of (package, function_name) pairs from mined CVE data
    cve_functions = {}  # package -> set of function names
    for r in cve_patches:
        if r.get('functions_mined'):
            pkg = r['affected_package']
            if pkg not in cve_functions:
                cve_functions[pkg] = set()
            for fn in r['functions_mined'].split(';'):
                fn = fn.strip()
                if fn:
                    cve_functions[pkg].add(fn)

    total_cve_funcs = sum(len(fns) for fns in cve_functions.values())
    print(f"\n  CVE function ground truth: {total_cve_funcs} functions across {len(cve_functions)} packages")
    for pkg, fns in sorted(cve_functions.items()):
        print(f"    {pkg}: {len(fns)} functions")

    # Function-level Precision@K: "Of the top-K methods, how many are
    # actual CVE-affected functions (exact function name match)?"
    rq1b_results = []

    for root_pkg in cl_by_root:
        methods = cl_by_root[root_pkg]
        if not methods:
            continue

        # Check if any dependency in this root's analysis has CVE functions
        dep_pkgs = set(m['dependency_package'] for m in methods)
        relevant_cve_pkgs = dep_pkgs & set(cve_functions.keys())
        if not relevant_cve_pkgs:
            continue

        # Build the ground truth set for this root's supply chain
        gt_funcs = set()
        for pkg in relevant_cve_pkgs:
            for fn in cve_functions[pkg]:
                gt_funcs.add((pkg, fn))

        # Sort by each strategy
        cl_sorted = sorted(methods, key=lambda m: safe_float(m['cross_level_risk']), reverse=True)
        method_sorted = sorted(methods, key=lambda m: safe_float(m['method_composite_risk']), reverse=True)
        eco_sorted = sorted(methods, key=lambda m: safe_float(m['ecosystem_fan_in']), reverse=True)

        def func_precision_at_k(sorted_methods, k, ground_truth):
            """Precision@K using exact function-level match."""
            top_k = sorted_methods[:k]
            hits = sum(1 for m in top_k
                       if (m['dependency_package'], m['method_name']) in ground_truth)
            return hits / k if k > 0 else 0

        for K in K_VALUES:
            p_cl = func_precision_at_k(cl_sorted, K, gt_funcs)
            p_method = func_precision_at_k(method_sorted, K, gt_funcs)
            p_eco = func_precision_at_k(eco_sorted, K, gt_funcs)

            rq1b_results.append({
                'root_package': root_pkg,
                'K': K,
                'func_precision_cross_level': round(p_cl, 4),
                'func_precision_method_only': round(p_method, 4),
                'func_precision_ecosystem_only': round(p_eco, 4),
                'n_cve_functions': len(gt_funcs),
                'n_total_methods': len(methods),
            })

    # Aggregate function-level results
    rq1b_roots = set(r['root_package'] for r in rq1b_results)
    print(f"\n  Root packages with function-level ground truth: {len(rq1b_roots)}")

    print(f"\n  {'K':>3}  {'FuncP@K (Cross-Level)':>22}  {'FuncP@K (Method-Only)':>22}  {'FuncP@K (Eco-Only)':>22}")
    print("  " + "-" * 75)

    rq1b_summary = {}
    for K in K_VALUES:
        k_results = [r for r in rq1b_results if r['K'] == K]
        if not k_results:
            continue

        avg_cl = avg([r['func_precision_cross_level'] for r in k_results])
        avg_method = avg([r['func_precision_method_only'] for r in k_results])
        avg_eco = avg([r['func_precision_ecosystem_only'] for r in k_results])

        rq1b_summary[K] = {
            'avg_func_p_cross_level': round(avg_cl, 4),
            'avg_func_p_method_only': round(avg_method, 4),
            'avg_func_p_eco_only': round(avg_eco, 4),
        }

        print(f"  {K:>3}  {avg_cl:>22.4f}  {avg_method:>22.4f}  {avg_eco:>22.4f}")

    # Save function-level results
    if rq1b_results:
        rq1b_path = OUTPUT_DIR / "rq1b_function_level_results.csv"
        with open(rq1b_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rq1b_results[0].keys())
            writer.writeheader()
            writer.writerows(rq1b_results)
        print(f"\n  → {rq1b_path.name} ({len(rq1b_results)} rows)")
else:
    print("  WARNING: cve_patch_analysis.csv not found — skipping function-level analysis")
    rq1b_results = []
    rq1b_summary = {}


# ══════════════════════════════════════════════════════════════
# RQ1c: STATISTICAL SIGNIFICANCE TESTS (Fix 2)
# Wilcoxon signed-rank + bootstrap confidence intervals
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("RQ1c: STATISTICAL SIGNIFICANCE TESTS")
print("=" * 70)

import random

def wilcoxon_signed_rank(x, y):
    """
    Wilcoxon signed-rank test (two-sided) for paired samples.
    Returns (W statistic, approximate p-value using normal approximation).
    Appropriate for small paired samples (n >= 6).
    """
    diffs = [xi - yi for xi, yi in zip(x, y)]
    # Remove zero differences
    diffs = [(abs(d), 1 if d > 0 else -1) for d in diffs if d != 0]
    if len(diffs) < 6:
        return None, None  # Too few non-zero differences

    n = len(diffs)
    # Rank by absolute value
    sorted_diffs = sorted(enumerate(diffs), key=lambda x: x[1][0])
    ranks = [0] * n
    i = 0
    while i < n:
        j = i
        while j < n and sorted_diffs[j][1][0] == sorted_diffs[i][1][0]:
            j += 1
        avg_rank = sum(range(i + 1, j + 1)) / (j - i)
        for k in range(i, j):
            ranks[sorted_diffs[k][0]] = avg_rank
        i = j

    # W+ = sum of ranks for positive differences
    w_plus = sum(ranks[i] for i in range(n) if diffs[i][1] > 0)
    w_minus = sum(ranks[i] for i in range(n) if diffs[i][1] < 0)
    W = min(w_plus, w_minus)

    # Normal approximation for p-value
    mean_W = n * (n + 1) / 4
    std_W = math.sqrt(n * (n + 1) * (2 * n + 1) / 24)
    if std_W == 0:
        return W, 1.0
    z = (W - mean_W) / std_W
    # Two-tailed p-value using normal CDF approximation
    p_value = 2 * (1 - _norm_cdf(abs(z)))
    return W, p_value

def _norm_cdf(z):
    """Approximation of standard normal CDF (Abramowitz & Stegun)."""
    if z < 0:
        return 1 - _norm_cdf(-z)
    a1, a2, a3, a4, a5 = 0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429
    p = 0.3275911
    t = 1.0 / (1.0 + p * z)
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-z * z / 2.0)
    return y

def bootstrap_ci(values, n_bootstrap=10000, ci=0.95, seed=42):
    """Bootstrap confidence interval for the mean."""
    rng = random.Random(seed)
    n = len(values)
    if n == 0:
        return 0, 0, 0
    means = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(values) for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    alpha = (1 - ci) / 2
    lo_idx = int(alpha * n_bootstrap)
    hi_idx = int((1 - alpha) * n_bootstrap)
    return sum(values) / n, means[lo_idx], means[hi_idx]

# Run statistical tests on package-level P@K (original RQ1)
print("\n  Package-Level P@K — Wilcoxon Signed-Rank Tests:")
print(f"  {'Comparison':<35} {'K':>3}  {'W':>6}  {'p-value':>10}  {'Significant?':>14}")
print("  " + "-" * 75)

for K in K_VALUES:
    k_results = [r for r in rq1_results if r['K'] == K]
    if len(k_results) < 6:
        print(f"  {'Cross-Level vs Method-Only':<35} {K:>3}  {'n/a':>6}  {'n<6':>10}  {'—':>14}")
        continue

    cl_vals = [r['precision_cross_level'] for r in k_results]
    method_vals = [r['precision_method_only'] for r in k_results]
    eco_vals = [r['precision_ecosystem_only'] for r in k_results]

    # Cross-level vs method-only
    W, p = wilcoxon_signed_rank(cl_vals, method_vals)
    sig = "Yes (p<0.05)" if p is not None and p < 0.05 else "No"
    W_s = f"{W:.1f}" if W is not None else "n/a"
    p_s = f"{p:.4f}" if p is not None else "n/a"
    print(f"  {'Cross-Level vs Method-Only':<35} {K:>3}  {W_s:>6}  {p_s:>10}  {sig:>14}")

    # Cross-level vs eco-only
    W2, p2 = wilcoxon_signed_rank(cl_vals, eco_vals)
    sig2 = "Yes (p<0.05)" if p2 is not None and p2 < 0.05 else "No"
    W2_s = f"{W2:.1f}" if W2 is not None else "n/a"
    p2_s = f"{p2:.4f}" if p2 is not None else "n/a"
    print(f"  {'Cross-Level vs Eco-Only':<35} {K:>3}  {W2_s:>6}  {p2_s:>10}  {sig2:>14}")

# Bootstrap confidence intervals
print(f"\n  Bootstrap 95% Confidence Intervals (10,000 iterations):")
print(f"  {'Strategy':<20} {'K':>3}  {'Mean':>8}  {'95% CI':>20}")
print("  " + "-" * 55)

for K in K_VALUES:
    k_results = [r for r in rq1_results if r['K'] == K]
    if not k_results:
        continue

    for label, key in [("Cross-Level", "precision_cross_level"),
                        ("Method-Only", "precision_method_only"),
                        ("Eco-Only", "precision_ecosystem_only")]:
        vals = [r[key] for r in k_results]
        mean_val, lo, hi = bootstrap_ci(vals)
        print(f"  {label:<20} {K:>3}  {mean_val:>8.4f}  [{lo:.4f}, {hi:.4f}]")
    print()

# Also run on function-level results if available
if rq1b_results:
    print(f"\n  Function-Level FuncP@K — Wilcoxon Signed-Rank Tests:")
    print(f"  {'Comparison':<35} {'K':>3}  {'W':>6}  {'p-value':>10}  {'Significant?':>14}")
    print("  " + "-" * 75)

    for K in K_VALUES:
        k_results = [r for r in rq1b_results if r['K'] == K]
        if len(k_results) < 6:
            print(f"  {'Cross-Level vs Method-Only':<35} {K:>3}  {'n/a':>6}  {'n<6':>10}  {'—':>14}")
            continue

        cl_vals = [r['func_precision_cross_level'] for r in k_results]
        method_vals = [r['func_precision_method_only'] for r in k_results]
        eco_vals = [r['func_precision_ecosystem_only'] for r in k_results]

        W, p = wilcoxon_signed_rank(cl_vals, method_vals)
        sig = "Yes (p<0.05)" if p is not None and p < 0.05 else "No"
        p_str = f"{p:.4f}" if p is not None else "n/a"
        W_str = f"{W:.1f}" if W is not None else "n/a"
        print(f"  {'Cross-Level vs Method-Only':<35} {K:>3}  {W_str:>6}  {p_str:>10}  {sig:>14}")

        W2, p2 = wilcoxon_signed_rank(cl_vals, eco_vals)
        sig2 = "Yes (p<0.05)" if p2 is not None and p2 < 0.05 else "No"
        p2_str = f"{p2:.4f}" if p2 is not None else "n/a"
        W2_str = f"{W2:.1f}" if W2 is not None else "n/a"
        print(f"  {'Cross-Level vs Eco-Only':<35} {K:>3}  {W2_str:>6}  {p2_str:>10}  {sig2:>14}")

    print(f"\n  Function-Level Bootstrap 95% CIs:")
    print(f"  {'Strategy':<20} {'K':>3}  {'Mean':>8}  {'95% CI':>20}")
    print("  " + "-" * 55)

    for K in K_VALUES:
        k_results = [r for r in rq1b_results if r['K'] == K]
        if not k_results:
            continue
        for label, key in [("Cross-Level", "func_precision_cross_level"),
                            ("Method-Only", "func_precision_method_only"),
                            ("Eco-Only", "func_precision_ecosystem_only")]:
            vals = [r[key] for r in k_results]
            mean_val, lo, hi = bootstrap_ci(vals)
            print(f"  {label:<20} {K:>3}  {mean_val:>8.4f}  [{lo:.4f}, {hi:.4f}]")
        print()


# ══════════════════════════════════════════════════════════════
# RQ2: REACHABILITY FILTERING
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("RQ2: REACHABILITY FILTERING")
print("CVE false-positive reduction potential")
print("=" * 70)

# Analyze vulnerability reachability status distribution
reachability_dist = Counter(v['reachability_status'] for v in vulns if v.get('reachability_status'))
severity_dist = Counter(v['severity'] for v in vulns)

# CVEs with vs without affected function data
has_func_data = sum(1 for v in vulns if v.get('has_affected_functions') == 'True')
no_func_data = sum(1 for v in vulns if v.get('has_affected_functions') == 'False' or not v.get('has_affected_functions'))

# Unique affected packages with CVEs
unique_vuln_packages = set(v['affected_package'] for v in vulns)

# Cross-reference: which vulnerable packages also appear in cross-level results?
cl_packages = set(row['dependency_package'] for row in cross_level)
vuln_in_cl = unique_vuln_packages & cl_packages
vuln_not_in_cl = unique_vuln_packages - cl_packages

# Analysis: what if we could suppress unreachable CVEs?
# Since OSV doesn't provide affected_functions, we estimate the potential
# using method coverage: packages where we have call graphs and could
# theoretically perform reachability analysis.
packages_with_callgraph = set(row['package'] for row in hotspots)
vuln_with_callgraph = unique_vuln_packages & packages_with_callgraph

# Resolution rate for vulnerable packages
vuln_pkg_rr = {}
for p in corpus:
    if p['package'] in unique_vuln_packages and p['resolution_rate']:
        vuln_pkg_rr[p['package']] = safe_float(p['resolution_rate'])

high_rr_vuln_pkgs = {k: v for k, v in vuln_pkg_rr.items() if v >= 0.85}

rq2_summary = {
    'total_cve_records': len(vulns),
    'unique_cves': len(all_unique_cves),
    'unique_affected_packages': len(unique_vuln_packages),
    'severity_distribution': dict(severity_dist),
    'reachability_distribution': dict(reachability_dist),
    'cves_with_affected_functions': has_func_data,
    'cves_without_affected_functions': no_func_data,
    'vuln_packages_with_callgraph': len(vuln_with_callgraph),
    'vuln_packages_with_high_rr': len(high_rr_vuln_pkgs),
    'avg_resolution_rate_vuln_pkgs': avg(list(vuln_pkg_rr.values())) if vuln_pkg_rr else 0,
}

print(f"\n  Total CVE records:           {rq2_summary['total_cve_records']}")
print(f"  Unique CVEs:                 {rq2_summary['unique_cves']}")
print(f"  Unique affected packages:    {rq2_summary['unique_affected_packages']}")
print(f"\n  Severity distribution:")
for sev in ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN']:
    count = severity_dist.get(sev, 0)
    pct = count / len(vulns) * 100 if vulns else 0
    print(f"    {sev:<10} {count:>3} ({pct:.1f}%)")

print(f"\n  CVEs with affected_functions:    {has_func_data} ({has_func_data/len(vulns)*100:.1f}%)")
print(f"  CVEs without affected_functions: {no_func_data} ({no_func_data/len(vulns)*100:.1f}%)")

print(f"\n  Reachability analysis potential:")
print(f"    Vuln packages with call graphs: {len(vuln_with_callgraph)}/{len(unique_vuln_packages)}")
print(f"    Vuln packages with R≥0.85:      {len(high_rr_vuln_pkgs)}/{len(unique_vuln_packages)}")
if vuln_pkg_rr:
    print(f"    Avg resolution rate (vuln pkgs): {avg(list(vuln_pkg_rr.values())):.1%}")

# Theoretical filtering analysis: for packages where we COULD do reachability
# analysis (have call graph + high resolution rate), estimate what fraction
# of their methods are reachable from public entry points.
print(f"\n  Method reachability coverage (vuln packages with call graph):")
for pkg in sorted(vuln_with_callgraph):
    pkg_hotspots = [h for h in hotspots if h['package'] == pkg]
    if pkg_hotspots:
        total = len(pkg_hotspots)
        orphans = sum(1 for h in pkg_hotspots if h.get('is_orphan') == 'True')
        leaves = sum(1 for h in pkg_hotspots if h.get('is_leaf') == 'True')
        rr = vuln_pkg_rr.get(pkg, 0)
        print(f"    {pkg:<25} methods={total:>3}  orphans={orphans:>3} ({orphans/total*100:.0f}%)  R={rr:.0%}")


# ══════════════════════════════════════════════════════════════
# RQ3: FORMULA SENSITIVITY
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("RQ3: FORMULA SENSITIVITY")
print("Rank stability across formula variants")
print("=" * 70)

# Spearman rank correlation between formula variants
def spearman_rank_correlation(x_vals, y_vals):
    """Compute Spearman's rank correlation coefficient."""
    n = len(x_vals)
    if n < 2:
        return 0.0
    
    # Rank the values
    def rank(vals):
        sorted_idx = sorted(range(n), key=lambda i: vals[i])
        ranks = [0] * n
        for rank_pos, idx in enumerate(sorted_idx):
            ranks[idx] = rank_pos + 1
        return ranks
    
    rx = rank(x_vals)
    ry = rank(y_vals)
    
    # Spearman: 1 - (6 * sum(d²)) / (n * (n² - 1))
    d_sq_sum = sum((rx[i] - ry[i]) ** 2 for i in range(n))
    rho = 1 - (6 * d_sq_sum) / (n * (n * n - 1))
    return rho

# Extract the four formula variant scores
formula_variants = {
    'log10': [],
    'log2': [],
    'sqrt': [],
    'linear': [],
}

for row in cross_level:
    formula_variants['log10'].append(safe_float(row['cl_risk_log10']))
    formula_variants['log2'].append(safe_float(row['cl_risk_log2']))
    formula_variants['sqrt'].append(safe_float(row['cl_risk_sqrt']))
    formula_variants['linear'].append(safe_float(row['cl_risk_linear']))

# Pairwise Spearman correlations
variant_names = ['log10', 'log2', 'sqrt', 'linear']
print(f"\n  Spearman Rank Correlation Matrix (n={len(cross_level)} methods):")
print(f"\n  {'':>10}", end='')
for name in variant_names:
    print(f"  {name:>10}", end='')
print()

rq3_correlations = {}
for v1 in variant_names:
    print(f"  {v1:>10}", end='')
    for v2 in variant_names:
        rho = spearman_rank_correlation(formula_variants[v1], formula_variants[v2])
        pair_key = f"{v1}_vs_{v2}"
        rq3_correlations[pair_key] = round(rho, 4)
        print(f"  {rho:>10.4f}", end='')
    print()

# Per-root-package rank agreement analysis
print(f"\n  Top-3 rank agreement per root package:")
agreement_scores = []

for root_pkg, methods in cl_by_root.items():
    if len(methods) < 3:
        continue
    
    # Get top-3 by each variant
    top3_log10 = set(m['method_name'] for m in sorted(methods, key=lambda m: safe_float(m['cl_risk_log10']), reverse=True)[:3])
    top3_log2 = set(m['method_name'] for m in sorted(methods, key=lambda m: safe_float(m['cl_risk_log2']), reverse=True)[:3])
    top3_sqrt = set(m['method_name'] for m in sorted(methods, key=lambda m: safe_float(m['cl_risk_sqrt']), reverse=True)[:3])
    top3_linear = set(m['method_name'] for m in sorted(methods, key=lambda m: safe_float(m['cl_risk_linear']), reverse=True)[:3])
    
    # Jaccard similarity between log10 reference and each variant
    jaccard_log2 = len(top3_log10 & top3_log2) / len(top3_log10 | top3_log2) if top3_log10 | top3_log2 else 1
    jaccard_sqrt = len(top3_log10 & top3_sqrt) / len(top3_log10 | top3_sqrt) if top3_log10 | top3_sqrt else 1
    jaccard_linear = len(top3_log10 & top3_linear) / len(top3_log10 | top3_linear) if top3_log10 | top3_linear else 1
    
    agreement_scores.append({
        'root_package': root_pkg,
        'jaccard_log2': jaccard_log2,
        'jaccard_sqrt': jaccard_sqrt,
        'jaccard_linear': jaccard_linear,
    })

avg_jaccard_log2 = avg([s['jaccard_log2'] for s in agreement_scores])
avg_jaccard_sqrt = avg([s['jaccard_sqrt'] for s in agreement_scores])
avg_jaccard_linear = avg([s['jaccard_linear'] for s in agreement_scores])

print(f"    log10 vs log2:   Jaccard={avg_jaccard_log2:.4f}  (avg over {len(agreement_scores)} packages)")
print(f"    log10 vs sqrt:   Jaccard={avg_jaccard_sqrt:.4f}")
print(f"    log10 vs linear: Jaccard={avg_jaccard_linear:.4f}")

# Distributional statistics for each variant
print(f"\n  Distributional Statistics:")
print(f"  {'Variant':>10}  {'Mean':>12}  {'Median':>12}  {'Max':>12}  {'Std Dev':>12}")
print("  " + "-" * 65)

rq3_stats = {}
for name in variant_names:
    vals = formula_variants[name]
    mean_v = avg(vals)
    med_v = median(vals)
    max_v = max(vals)
    variance = sum((x - mean_v) ** 2 for x in vals) / len(vals)
    std_v = math.sqrt(variance)
    
    rq3_stats[name] = {
        'mean': round(mean_v, 4),
        'median': round(med_v, 4),
        'max': round(max_v, 4),
        'std': round(std_v, 4),
    }
    
    print(f"  {name:>10}  {mean_v:>12.4f}  {med_v:>12.4f}  {max_v:>12.4f}  {std_v:>12.4f}")


# ══════════════════════════════════════════════════════════════
# SUPPLEMENTARY: Cross-Level Score Distribution
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SUPPLEMENTARY ANALYSIS")
print("=" * 70)

# Cross-level risk score distribution
cl_scores = [safe_float(row['cross_level_risk']) for row in cross_level]
print(f"\n  Cross-Level Risk Distribution (n={len(cl_scores)}):")
print(f"    Mean:   {avg(cl_scores):.4f}")
print(f"    Median: {median(cl_scores):.4f}")
print(f"    Max:    {max(cl_scores):.4f}")
print(f"    Min:    {min(cl_scores):.4f}")

# Histogram buckets
buckets = [0, 1, 5, 10, 15, 20, 25, 30]
print(f"\n  Score distribution:")
for i in range(len(buckets) - 1):
    lo, hi = buckets[i], buckets[i + 1]
    count = sum(1 for s in cl_scores if lo <= s < hi)
    bar = '█' * (count // 5)
    print(f"    [{lo:>2}, {hi:>2}): {count:>4}  {bar}")
count_above = sum(1 for s in cl_scores if s >= buckets[-1])
bar = '█' * (count_above // 5)
print(f"    [{buckets[-1]:>2},  ∞): {count_above:>4}  {bar}")

# Hidden amplifier analysis
print(f"\n  Hidden Amplifier Detection:")
print(f"  Packages with fan-in > 10,000:")
for p in sorted(corpus, key=lambda x: safe_float(x.get('global_fan_in', 0)), reverse=True):
    fi = safe_float(p.get('global_fan_in', 0))
    if fi >= 10000:
        mc = safe_int(p.get('method_count', 0))
        loc = safe_int(p.get('total_loc', 0))
        label = "AMPLIFIER" if mc < 50 and fi > 50000 else ""
        print(f"    {p['ecosystem']}/{p['package']:<25} fan_in={fi:>10,.0f}  methods={mc:>4}  LOC={loc:>6}  {label}")


# ══════════════════════════════════════════════════════════════
# SAVE RESULTS
# ══════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SAVING RESULTS")
print("=" * 70)

# RQ1 results
rq1_path = OUTPUT_DIR / "rq1_results.csv"
with open(rq1_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=rq1_results[0].keys())
    writer.writeheader()
    writer.writerows(rq1_results)
print(f"  → {rq1_path.name} ({len(rq1_results)} rows)")

# RQ3 results
rq3_path = OUTPUT_DIR / "rq3_results.csv"
with open(rq3_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=agreement_scores[0].keys())
    writer.writeheader()
    writer.writerows(agreement_scores)
print(f"  → {rq3_path.name} ({len(agreement_scores)} rows)")

# Comprehensive summary for §5
summary_path = OUTPUT_DIR / "experiment_summary.txt"
with open(summary_path, 'w') as f:
    f.write("=" * 70 + "\n")
    f.write("OSCAR EXPERIMENT SUMMARY — FOR §5 EVALUATION\n")
    f.write(f"Generated: {datetime.now().isoformat()}\n")
    f.write("=" * 70 + "\n\n")
    
    f.write("TABLE 1: CORPUS SUMMARY\n")
    f.write("-" * 40 + "\n")
    f.write(f"Metric                  npm     PyPI\n")
    f.write(f"Packages                {corpus_stats['npm_packages']:>3}     {corpus_stats['pypi_packages']:>3}\n")
    f.write(f"Avg methods/package     {corpus_stats['npm_avg_methods']:>6.0f}  {corpus_stats['pypi_avg_methods']:>6.0f}\n")
    f.write(f"Avg resolution rate     {corpus_stats['npm_avg_resolution_rate']:>5.1%}  {corpus_stats['pypi_avg_resolution_rate']:>5.1%}\n")
    f.write(f"Avg LOC                 {corpus_stats['npm_avg_loc']:>6.0f}  {corpus_stats['pypi_avg_loc']:>6.0f}\n")
    f.write(f"Unique CVEs             {corpus_stats['npm_unique_cves']:>3}     {corpus_stats['pypi_unique_cves']:>3}\n\n")
    
    f.write("RQ1: PRECISION@K\n")
    f.write("-" * 40 + "\n")
    for K, data in rq1_summary.items():
        f.write(f"P@{K}: Cross-Level={data['avg_precision_cross_level']:.4f}  "
                f"Method-Only={data['avg_precision_method_only']:.4f}  "
                f"Eco-Only={data['avg_precision_eco_only']:.4f}  "
                f"Improvement={data['improvement_pct']:+.1f}%\n")
    
    f.write(f"\nnDCG:\n")
    for K, data in ndcg_results.items():
        f.write(f"nDCG@{K}: Cross-Level={data['ndcg_cross_level']:.4f}  "
                f"Method-Only={data['ndcg_method_only']:.4f}  "
                f"Eco-Only={data['ndcg_eco_only']:.4f}\n")
    
    f.write(f"\nRQ2: VULNERABILITY ANALYSIS\n")
    f.write("-" * 40 + "\n")
    f.write(f"Total CVE records: {rq2_summary['total_cve_records']}\n")
    f.write(f"Unique CVEs: {rq2_summary['unique_cves']}\n")
    f.write(f"Severity: CRITICAL={severity_dist.get('CRITICAL',0)}, HIGH={severity_dist.get('HIGH',0)}, MODERATE={severity_dist.get('MODERATE',0)}, LOW={severity_dist.get('LOW',0)}\n")
    f.write(f"CVEs with affected_functions: {rq2_summary['cves_with_affected_functions']}/{len(vulns)} ({rq2_summary['cves_with_affected_functions']/len(vulns)*100:.1f}%)\n")
    f.write(f"Vuln packages with call graphs: {rq2_summary['vuln_packages_with_callgraph']}/{rq2_summary['unique_affected_packages']}\n")
    f.write(f"Vuln packages with R≥0.85: {rq2_summary['vuln_packages_with_high_rr']}/{rq2_summary['unique_affected_packages']}\n")
    
    f.write(f"\nRQ3: FORMULA SENSITIVITY\n")
    f.write("-" * 40 + "\n")
    f.write(f"Spearman correlations vs log10:\n")
    f.write(f"  log10 vs log2:   ρ={rq3_correlations.get('log10_vs_log2', 0)}\n")
    f.write(f"  log10 vs sqrt:   ρ={rq3_correlations.get('log10_vs_sqrt', 0)}\n")
    f.write(f"  log10 vs linear: ρ={rq3_correlations.get('log10_vs_linear', 0)}\n")
    f.write(f"\nTop-3 Jaccard agreement (avg):\n")
    f.write(f"  log10 vs log2:   {avg_jaccard_log2:.4f}\n")
    f.write(f"  log10 vs sqrt:   {avg_jaccard_sqrt:.4f}\n")
    f.write(f"  log10 vs linear: {avg_jaccard_linear:.4f}\n")

print(f"  → {summary_path.name}")

print(f"\n{'=' * 70}")
print("ANALYSIS COMPLETE")
print(f"{'=' * 70}")
