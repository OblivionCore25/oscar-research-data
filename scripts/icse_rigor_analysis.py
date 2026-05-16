#!/usr/bin/env python3
"""
ICSE 2027 Mathematical Rigor Analysis
======================================
Implements Rigor 1-6 from the implementation plan:
  1. Bootstrap confidence intervals on P@K and nDCG
  3. Alternative formula comparison
  4. CR component ablation + feature importance
  5. Fan-in variance analysis (Kendall τ vs σ²_F)
  6. n expansion via dataset consolidation

Uses existing data from:
  - oscar-research-data/data/cross_level_results.csv (21 roots, 825 rows)
  - oscar-research-data-icse/exports/cve_patch_analysis.csv (162 advisories)

Output: Tables formatted for LaTeX insertion.
"""

import csv
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats

# ============================================================================
# DATA LOADING
# ============================================================================

BASE = Path(__file__).resolve().parent.parent
OLDER_CLR = BASE / "data" / "cross_level_results.csv"
ICSE_CLR = BASE.parent / "oscar-research-data-icse" / "exports" / "cross_level_results_20260514_200556.csv"
CVE_PATCH = BASE.parent / "oscar-research-data-icse" / "exports" / "cve_patch_analysis.csv"


def load_clr_data(filepath):
    """Load cross-level results CSV into list of dicts."""
    rows = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse numeric fields
            for field in ['complexity', 'method_blast_radius', 'method_centrality',
                          'change_frequency', 'method_composite_risk', 'ecosystem_fan_in',
                          'bottleneck_score', 'cross_level_risk', 'cl_risk_log10',
                          'cl_risk_log2', 'cl_risk_sqrt', 'cl_risk_linear']:
                try:
                    row[field] = float(row[field])
                except (ValueError, KeyError):
                    row[field] = 0.0
            rows.append(row)
    return rows


def load_cve_patch_data(filepath):
    """Load CVE patch analysis to get ground truth: which packages have mined functions."""
    pkg_functions = defaultdict(set)  # package -> set of mined function names
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('num_functions_mined', '0') != '0' and row.get('functions_mined', ''):
                pkg = row['affected_package']
                for func in row['functions_mined'].split(';'):
                    func = func.strip()
                    if func:
                        pkg_functions[pkg].add(func)
    return pkg_functions


# ============================================================================
# GROUND TRUTH: Map mined vulnerable functions to CLR rows
# ============================================================================

def build_ground_truth(clr_rows, cve_functions):
    """
    For each root package, mark which methods in its dependency tree
    are in CVE-bearing packages with mined functions.
    
    Returns: dict[root_package] -> list of (method_row, is_vulnerable)
    """
    root_data = defaultdict(list)
    for row in clr_rows:
        root = row['root_package']
        dep_pkg = row['dependency_package']
        method = row['method_name']
        
        # A method is "vulnerable" if its package has mined CVE functions
        # AND this specific method is one of those functions
        is_vuln_pkg = dep_pkg in cve_functions
        is_vuln_func = method in cve_functions.get(dep_pkg, set())
        
        root_data[root].append({
            'row': row,
            'is_vuln_pkg': is_vuln_pkg,
            'is_vuln_func': is_vuln_func,
        })
    
    return root_data


# ============================================================================
# RIGOR 1: Bootstrap Confidence Intervals
# ============================================================================

def precision_at_k(ranked_items, k):
    """Compute P@K: fraction of top-K items that are in CVE-bearing packages."""
    top_k = ranked_items[:k]
    if not top_k:
        return 0.0
    hits = sum(1 for item in top_k if item['is_vuln_pkg'])
    return hits / len(top_k)


def dcg_at_k(ranked_items, k):
    """Compute DCG@K with binary relevance."""
    dcg = 0.0
    for i, item in enumerate(ranked_items[:k]):
        rel = 1.0 if item['is_vuln_pkg'] else 0.0
        dcg += rel / math.log2(i + 2)  # i+2 because i is 0-indexed
    return dcg


def ndcg_at_k(ranked_items, k):
    """Compute nDCG@K."""
    dcg = dcg_at_k(ranked_items, k)
    # Ideal: all relevant items first
    ideal_items = sorted(ranked_items, key=lambda x: x['is_vuln_pkg'], reverse=True)
    idcg = dcg_at_k(ideal_items, k)
    if idcg == 0:
        return 0.0
    return dcg / idcg


def compute_metrics_for_root(items, ranking_key, ks=[3, 5, 10]):
    """Compute P@K and nDCG@K for a root package using a given ranking key."""
    # Sort by ranking_key descending
    ranked = sorted(items, key=lambda x: x['row'][ranking_key], reverse=True)
    
    results = {}
    for k in ks:
        results[f'P@{k}'] = precision_at_k(ranked, k)
        results[f'nDCG@{k}'] = ndcg_at_k(ranked, k)
    return results


def bootstrap_ci(root_data, ranking_key, n_bootstrap=10000, ci=0.95, ks=[3, 5, 10]):
    """
    Compute bootstrap confidence intervals for P@K and nDCG@K.
    
    Resamples over root packages (not individual methods).
    """
    # Only include roots with enough methods and at least 1 CVE-bearing dep
    eligible_roots = []
    for root, items in root_data.items():
        has_vuln = any(item['is_vuln_pkg'] for item in items)
        if has_vuln and len(items) >= 10:
            eligible_roots.append(root)
    
    if not eligible_roots:
        print("WARNING: No eligible root packages for P@K evaluation")
        return {}
    
    print(f"\n{'='*70}")
    print(f"RIGOR 1: Bootstrap CIs (n={len(eligible_roots)}, B={n_bootstrap})")
    print(f"{'='*70}")
    print(f"Eligible roots: {eligible_roots}")
    
    # Compute point estimates
    root_metrics = {}
    for root in eligible_roots:
        root_metrics[root] = compute_metrics_for_root(root_data[root], ranking_key)
    
    # Point estimates (mean across roots)
    metric_names = [f'{m}@{k}' for m in ['P', 'nDCG'] for k in ks]
    point_estimates = {}
    for metric in metric_names:
        values = [root_metrics[root][metric] for root in eligible_roots]
        point_estimates[metric] = np.mean(values)
    
    # Bootstrap
    alpha = 1 - ci
    boot_results = {m: [] for m in metric_names}
    
    rng = np.random.default_rng(42)
    for _ in range(n_bootstrap):
        sample_roots = rng.choice(eligible_roots, size=len(eligible_roots), replace=True)
        for metric in metric_names:
            values = [root_metrics[r][metric] for r in sample_roots]
            boot_results[metric].append(np.mean(values))
    
    # Compute CIs
    results = {}
    print(f"\n{'Metric':<10} {'Point':>8} {'CI_low':>8} {'CI_high':>8}")
    print("-" * 40)
    for metric in metric_names:
        boot_arr = np.array(boot_results[metric])
        ci_low = np.percentile(boot_arr, 100 * alpha / 2)
        ci_high = np.percentile(boot_arr, 100 * (1 - alpha / 2))
        results[metric] = {
            'point': point_estimates[metric],
            'ci_low': ci_low,
            'ci_high': ci_high,
        }
        print(f"{metric:<10} {point_estimates[metric]:>8.4f} [{ci_low:>7.4f}, {ci_high:>7.4f}]")
    
    return results


# ============================================================================
# RIGOR 3: Alternative Formula Comparison
# ============================================================================

def compute_alternative_formulas(clr_rows):
    """Add alternative formula scores to each row."""
    for row in clr_rows:
        cr = row['method_composite_risk']
        fi = row['ecosystem_fan_in']
        log_fi = math.log10(max(fi, 1))
        
        # Multiplicative (original CLR)
        row['clr_multiplicative'] = cr * log_fi
        
        # Additive: CR + α * log10(FI), α chosen to normalize scales
        # Use α = mean(CR) / mean(log_fi) across all rows
        row['_cr'] = cr
        row['_log_fi'] = log_fi
        
        # Geometric mean: sqrt(CR * log10(FI))
        row['clr_geometric'] = math.sqrt(max(cr * log_fi, 0))
    
    # Compute α for additive (needs global stats)
    all_cr = [r['_cr'] for r in clr_rows if r['_cr'] > 0]
    all_logfi = [r['_log_fi'] for r in clr_rows if r['_log_fi'] > 0]
    if all_cr and all_logfi:
        alpha = np.mean(all_cr) / np.mean(all_logfi)
    else:
        alpha = 1.0
    
    for row in clr_rows:
        row['clr_additive'] = row['_cr'] + alpha * row['_log_fi']
    
    # Rank-product: rank(CR) * rank(FI)
    # Compute ranks per root package
    roots = defaultdict(list)
    for row in clr_rows:
        roots[row['root_package']].append(row)
    
    for root, items in roots.items():
        cr_sorted = sorted(items, key=lambda x: x['method_composite_risk'], reverse=True)
        fi_sorted = sorted(items, key=lambda x: x['ecosystem_fan_in'], reverse=True)
        
        for rank, item in enumerate(cr_sorted, 1):
            item['_cr_rank'] = rank
        for rank, item in enumerate(fi_sorted, 1):
            item['_fi_rank'] = rank
        
        for item in items:
            item['clr_rank_product'] = item['_cr_rank'] * item['_fi_rank']
    
    return clr_rows


def compare_formulas(root_data, ks=[3, 5, 10]):
    """Compare P@K across formula variants."""
    formulas = {
        'CLR (mult.)': 'cross_level_risk',
        'CR only': 'method_composite_risk',
        'FI only': 'ecosystem_fan_in',
        'Additive': 'clr_additive',
        'Geometric': 'clr_geometric',
    }
    
    # Rank-product uses inverse ranking (lower = better)
    
    eligible_roots = [
        root for root, items in root_data.items()
        if any(item['is_vuln_pkg'] for item in items) and len(items) >= 10
    ]
    
    print(f"\n{'='*70}")
    print(f"RIGOR 3: Alternative Formula Comparison (n={len(eligible_roots)})")
    print(f"{'='*70}")
    
    for formula_name, key in formulas.items():
        metrics = defaultdict(list)
        for root in eligible_roots:
            items = root_data[root]
            ranked = sorted(items, key=lambda x: x['row'][key], reverse=True)
            for k in ks:
                metrics[f'P@{k}'].append(precision_at_k(ranked, k))
                metrics[f'nDCG@{k}'].append(ndcg_at_k(ranked, k))
        
        print(f"\n{formula_name}:")
        for metric_name in [f'P@{k}' for k in ks] + [f'nDCG@{k}' for k in ks]:
            vals = metrics[metric_name]
            print(f"  {metric_name}: {np.mean(vals):.4f} (±{np.std(vals):.4f})")
    
    # Rank-product (lower = better, so sort ascending)
    print(f"\nRank-Product:")
    metrics = defaultdict(list)
    for root in eligible_roots:
        items = root_data[root]
        ranked = sorted(items, key=lambda x: x['row'].get('clr_rank_product', 999))
        for k in ks:
            metrics[f'P@{k}'].append(precision_at_k(ranked, k))
            metrics[f'nDCG@{k}'].append(ndcg_at_k(ranked, k))
    
    for metric_name in [f'P@{k}' for k in ks] + [f'nDCG@{k}' for k in ks]:
        vals = metrics[metric_name]
        print(f"  {metric_name}: {np.mean(vals):.4f} (±{np.std(vals):.4f})")


# ============================================================================
# RIGOR 4: CR Component Ablation + Feature Importance
# ============================================================================

def _back_compute_temporal_factor(row):
    """Back-compute temporal_factor from composite_risk and structural components.
    
    The Method Observatory hotspots endpoint computes:
        structural_risk = complexity × centrality × blast_radius
        temporal_factor  = max(log₂(1 + file_commits), 1.0)  [from git churn]
        composite_risk   = structural_risk × temporal_factor
    
    So: temporal_factor = composite_risk / structural_risk  (when structural > 0)
    
    NOTE: Only 2/20 dependency packages (urllib3, charset-normalizer) had git
    repos analyzed. The rest default to temporal_factor = 1.0.
    """
    comp = row['complexity']
    blast = row['method_blast_radius']
    cent = row['method_centrality']
    cr = row['method_composite_risk']
    structural = comp * cent * blast
    if structural > 0 and cr > 0:
        return cr / structural
    return 1.0


def ablation_study(root_data):
    """Remove each CR component and measure ranking impact.
    
    Uses MULTIPLICATIVE ablation matching the real CR formula:
        CR = complexity × centrality × blast_radius × temporal_factor
    Removing a component = dividing it out of composite_risk.
    """
    components = ['complexity', 'method_blast_radius', 'method_centrality', 'temporal_factor']
    
    print(f"\n{'='*70}")
    print("RIGOR 4A: CR Component Ablation (multiplicative)")
    print(f"{'='*70}")
    print("  Formula: CR = complexity × centrality × blast_radius × temporal_factor")
    print("  NOTE: temporal_factor available for 2/20 deps (urllib3, charset-normalizer)")
    
    # First, compute full CR rankings and back-compute temporal_factor
    all_methods = []
    for root, items in root_data.items():
        for item in items:
            r = item['row']
            r['temporal_factor'] = _back_compute_temporal_factor(r)
            all_methods.append(r)
    
    # Count temporal coverage
    n_with_temporal = sum(1 for r in all_methods if r['temporal_factor'] > 1.0)
    print(f"  Methods with temporal_factor > 1: {n_with_temporal}/{len(all_methods)} ({n_with_temporal/len(all_methods)*100:.1f}%)")
    
    # Full CR values
    full_cr = [r['method_composite_risk'] for r in all_methods]
    
    print(f"\n  {'Removed':<25s} {'Spearman ρ':>12} {'p-value':>12}")
    print(f"  {'-'*50}")
    
    for removed in components:
        # Multiplicative ablation: CR_ablated = CR / removed_component
        ablated_cr = []
        for r in all_methods:
            divisor = r[removed]
            if divisor > 0 and r['method_composite_risk'] > 0:
                ablated_cr.append(r['method_composite_risk'] / divisor)
            else:
                # If divisor is 0, the whole product was 0 anyway
                ablated_cr.append(r['method_composite_risk'])
        
        rho, p_val = stats.spearmanr(full_cr, ablated_cr)
        print(f"  –{removed:<25s} {rho:>11.4f}  {p_val:>11.2e}")


def feature_importance(root_data, cve_functions):
    """Compute feature importance: correlation of each CR component with CVE presence.
    
    Uses back-computed temporal_factor instead of the hardcoded-zero change_frequency.
    """
    components = ['complexity', 'method_blast_radius', 'method_centrality', 'temporal_factor']
    
    print(f"\n{'='*70}")
    print("RIGOR 4B: Feature Importance (CR components vs CVE presence)")
    print(f"{'='*70}")
    print("  NOTE: temporal_factor has limited coverage (3.6% of methods > 1.0)")
    
    # Collect all methods with their CVE status
    all_methods = []
    for root, items in root_data.items():
        for item in items:
            # Ensure temporal_factor is computed
            item['row']['temporal_factor'] = _back_compute_temporal_factor(item['row'])
            all_methods.append(item)
    
    for comp in components:
        vuln_values = [m['row'][comp] for m in all_methods if m['is_vuln_pkg']]
        non_vuln_values = [m['row'][comp] for m in all_methods if not m['is_vuln_pkg']]
        
        if not vuln_values or not non_vuln_values:
            print(f"  {comp}: insufficient data")
            continue
        
        # Spearman ρ
        all_vals = [m['row'][comp] for m in all_methods]
        all_labels = [1 if m['is_vuln_pkg'] else 0 for m in all_methods]
        rho, p_rho = stats.spearmanr(all_vals, all_labels)
        
        # Mann-Whitney U
        u_stat, p_mw = stats.mannwhitneyu(vuln_values, non_vuln_values, alternative='two-sided')
        
        # Cliff's δ
        n1, n2 = len(vuln_values), len(non_vuln_values)
        cliffs_d = (2 * u_stat) / (n1 * n2) - 1
        
        # Effect size interpretation
        if abs(cliffs_d) < 0.147:
            effect = "negligible"
        elif abs(cliffs_d) < 0.33:
            effect = "small"
        elif abs(cliffs_d) < 0.474:
            effect = "medium"
        else:
            effect = "large"
        
        print(f"\n  {comp}:")
        print(f"    Spearman ρ = {rho:.4f} (p = {p_rho:.2e})")
        print(f"    Mann-Whitney U = {u_stat:.0f} (p = {p_mw:.2e})")
        print(f"    Cliff's δ = {cliffs_d:.4f} ({effect})")
        print(f"    Vuln median = {np.median(vuln_values):.4f}, Non-vuln median = {np.median(non_vuln_values):.4f}")
        print(f"    n_vuln = {n1}, n_non_vuln = {n2}")


# ============================================================================
# RIGOR 5: Fan-in Variance Analysis
# ============================================================================

def fan_in_variance_analysis(root_data):
    """Compute Kendall τ between CLR and CR rankings per root, plot vs σ²_F."""
    
    print(f"\n{'='*70}")
    print("RIGOR 5: Fan-in Variance vs Ranking Divergence")
    print(f"{'='*70}")
    
    results = []
    for root, items in root_data.items():
        if len(items) < 5:
            continue
        
        clr_values = [item['row']['cross_level_risk'] for item in items]
        cr_values = [item['row']['method_composite_risk'] for item in items]
        log_fi_values = [math.log10(max(item['row']['ecosystem_fan_in'], 1)) for item in items]
        
        # Fan-in variance
        sigma2_f = np.var(log_fi_values)
        
        # Kendall τ between CLR and CR rankings
        if len(set(clr_values)) > 1 and len(set(cr_values)) > 1:
            tau, p_tau = stats.kendalltau(clr_values, cr_values)
        else:
            tau, p_tau = 1.0, 1.0
        
        # Top-10 Jaccard
        clr_top10 = set(sorted(range(len(items)), key=lambda i: clr_values[i], reverse=True)[:10])
        cr_top10 = set(sorted(range(len(items)), key=lambda i: cr_values[i], reverse=True)[:10])
        jaccard = len(clr_top10 & cr_top10) / len(clr_top10 | cr_top10) if clr_top10 | cr_top10 else 1.0
        
        results.append({
            'root': root,
            'n_methods': len(items),
            'sigma2_f': sigma2_f,
            'kendall_tau': tau,
            'jaccard_top10': jaccard,
            'fi_range': f"{min(log_fi_values):.1f}-{max(log_fi_values):.1f}",
        })
    
    results.sort(key=lambda x: x['sigma2_f'], reverse=True)
    
    print(f"\n{'Root':<15} {'n':>4} {'σ²_F':>8} {'τ(CLR,CR)':>10} {'Jaccard@10':>11} {'log₁₀(FI) range':>16}")
    print("-" * 70)
    for r in results:
        print(f"{r['root']:<15} {r['n_methods']:>4} {r['sigma2_f']:>8.4f} {r['kendall_tau']:>10.4f} {r['jaccard_top10']:>11.4f} {r['fi_range']:>16}")
    
    # Correlation between σ²_F and ranking divergence (1 - τ)
    if len(results) > 2:
        sigmas = [r['sigma2_f'] for r in results]
        divergences = [1 - r['kendall_tau'] for r in results]
        rho, p = stats.spearmanr(sigmas, divergences)
        print(f"\nCorrelation between σ²_F and ranking divergence (1-τ):")
        print(f"  Spearman ρ = {rho:.4f} (p = {p:.4f})")


# ============================================================================
# RIGOR 6: Dataset Consolidation Summary
# ============================================================================

def dataset_summary(older_rows, icse_rows, root_data):
    """Print consolidated dataset summary."""
    
    print(f"\n{'='*70}")
    print("RIGOR 6: Dataset Consolidation Summary")
    print(f"{'='*70}")
    
    older_roots = set(r['root_package'] for r in older_rows)
    icse_roots = set(r['root_package'] for r in icse_rows)
    
    print(f"\nOlder dataset: {len(older_roots)} root packages, {len(older_rows)} CLR rows")
    print(f"ICSE dataset:  {len(icse_roots)} root packages, {len(icse_rows)} CLR rows")
    print(f"Overlap: {older_roots & icse_roots}")
    print(f"Combined unique roots: {older_roots | icse_roots}")
    
    # Eligible roots for P@K
    eligible = []
    for root, items in root_data.items():
        has_vuln = any(item['is_vuln_pkg'] for item in items)
        if has_vuln and len(items) >= 10:
            eligible.append(root)
    
    print(f"\nRoots eligible for P@K (has CVE-bearing deps + ≥10 methods): {len(eligible)}")
    for root in sorted(eligible):
        items = root_data[root]
        n_vuln = sum(1 for i in items if i['is_vuln_pkg'])
        print(f"  {root}: {len(items)} methods, {n_vuln} in CVE-bearing deps")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("ICSE 2027 MATHEMATICAL RIGOR ANALYSIS")
    print("=" * 70)
    
    # Load data
    print("\nLoading data...")
    older_rows = load_clr_data(OLDER_CLR)
    print(f"  Older CLR: {len(older_rows)} rows")
    
    icse_rows = load_clr_data(ICSE_CLR)
    print(f"  ICSE CLR: {len(icse_rows)} rows")
    
    cve_functions = load_cve_patch_data(CVE_PATCH)
    print(f"  CVE patch data: {len(cve_functions)} packages with mined functions")
    print(f"  Total mined functions: {sum(len(v) for v in cve_functions.values())}")
    
    # Use older dataset (more root packages)
    # Add alternative formula scores
    older_rows = compute_alternative_formulas(older_rows)
    
    # Build ground truth
    root_data = build_ground_truth(older_rows, cve_functions)
    
    # Rigor 6: Dataset summary
    dataset_summary(older_rows, icse_rows, root_data)
    
    # Rigor 1: Bootstrap CIs
    bootstrap_ci(root_data, 'cross_level_risk')
    
    # Also compute for CR-only and FI-only for comparison
    print("\n--- CR-only bootstrap ---")
    bootstrap_ci(root_data, 'method_composite_risk')
    
    print("\n--- FI-only bootstrap ---")
    bootstrap_ci(root_data, 'ecosystem_fan_in')
    
    # Rigor 3: Formula comparison
    compare_formulas(root_data)
    
    # Rigor 4: Ablation + Feature importance
    ablation_study(root_data)
    feature_importance(root_data, cve_functions)
    
    # Rigor 5: Fan-in variance
    fan_in_variance_analysis(root_data)
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    main()
