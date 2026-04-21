#!/usr/bin/env python3
"""
OSCAR — CVE Patch Mining Script
================================
Automatically extracts affected function names from CVE fix commits.

Pipeline:
  1. Fetch GHSA advisory from GitHub API → extract fix commit URLs
  2. Fetch commit diff from GitHub
  3. Parse diff to find modified/added/deleted function names
  4. Cross-reference with Method Observatory call graph
  5. Run reachability analysis (BFS from entry points)
  6. Produce enriched vulnerability dataset

Usage:
    python research/scripts/mine_cve_patches.py

Output:
    research/data/cve_patch_analysis.csv
    research/data/rq2_reachability_results.csv
"""

import csv
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
METHOD_OBS_URL = "http://127.0.0.1:8001"

VULN_FILE = sorted(DATA_DIR.glob("vulnerability_results_*.csv"), reverse=True)[0]
HOTSPOTS_FILE = sorted(DATA_DIR.glob("method_hotspots_*.csv"), reverse=True)[0]

# Rate limiting for GitHub API (unauthenticated: 60 req/hour)
GITHUB_DELAY = 2.0  # seconds between requests


# ──────────────────────────────────────────────────────────────
# HTTP Helpers
# ──────────────────────────────────────────────────────────────

def fetch_json(url, retries=2):
    """Fetch JSON from URL with retries."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "OSCAR-Research/1.0",
    }
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  ⚠ Rate limited. Waiting 60s...")
                time.sleep(60)
                continue
            if e.code == 404:
                return None
            print(f"  ⚠ HTTP {e.code} for {url}")
            return None
        except Exception as e:
            if attempt < retries:
                time.sleep(2)
                continue
            print(f"  ⚠ Error fetching {url}: {e}")
            return None
    return None


def fetch_text(url, retries=2):
    """Fetch raw text from URL."""
    headers = {"User-Agent": "OSCAR-Research/1.0"}
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode(errors='replace')
        except urllib.error.HTTPError as e:
            if e.code == 403:
                time.sleep(60)
                continue
            return None
        except Exception:
            if attempt < retries:
                time.sleep(2)
                continue
            return None
    return None


# ──────────────────────────────────────────────────────────────
# Diff Parsing
# ──────────────────────────────────────────────────────────────

# Regex patterns for detecting function definitions in diffs
PYTHON_FUNC_PATTERNS = [
    re.compile(r'^\s*def\s+(\w+)\s*\('),         # def function_name(
    re.compile(r'^\s*async\s+def\s+(\w+)\s*\('),  # async def function_name(
    re.compile(r'^\s*class\s+(\w+)\s*[\(:]'),     # class ClassName(
]

JS_FUNC_PATTERNS = [
    re.compile(r'^\s*function\s+(\w+)\s*\('),            # function name(
    re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:function|async\s+function)\s*\('),  # const name = function(
    re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\)|[^=])\s*=>'),  # const name = (...) =>
    re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*\{'),           # method name() {
    re.compile(r'^\s*(?:async\s+)?(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'),  # name = () =>
    re.compile(r'^\s*exports\.(\w+)\s*='),               # exports.name =
    re.compile(r'^\s*module\.exports\.(\w+)\s*='),        # module.exports.name =
]

# Ignore common non-function names
IGNORE_NAMES = {
    'if', 'else', 'for', 'while', 'return', 'switch', 'case', 'try',
    'catch', 'throw', 'new', 'delete', 'typeof', 'void', 'True', 'False',
    'None', 'import', 'from', 'class', 'self', 'super', 'constructor',
    'describe', 'it', 'test', 'expect', 'beforeEach', 'afterEach',
}

# Ignore test files
TEST_PATH_PATTERNS = [
    re.compile(r'test[s]?/'),
    re.compile(r'__tests__/'),
    re.compile(r'\.test\.(js|py|ts)$'),
    re.compile(r'_test\.py$'),
    re.compile(r'spec[s]?/'),
]


def is_test_file(filepath):
    """Check if a filepath looks like a test file."""
    return any(p.search(filepath) for p in TEST_PATH_PATTERNS)


def extract_functions_from_diff(diff_text, ecosystem):
    """Parse a unified diff to extract modified function names.
    
    Strategy: Look at diff hunks (+/- lines) and also the @@ hunk headers
    which often contain the enclosing function name.
    """
    functions = set()
    patterns = PYTHON_FUNC_PATTERNS if ecosystem == 'pypi' else JS_FUNC_PATTERNS
    
    current_file = None
    
    for line in diff_text.split('\n'):
        # Track current file from diff headers
        if line.startswith('diff --git'):
            parts = line.split(' b/')
            if len(parts) >= 2:
                current_file = parts[-1].strip()
            continue
        
        # Skip test files
        if current_file and is_test_file(current_file):
            continue
        
        # Extract function from @@ hunk header (git includes enclosing context)
        # Format: @@ -start,count +start,count @@ function_context
        if line.startswith('@@'):
            hunk_match = re.search(r'@@.*@@\s*(.*)', line)
            if hunk_match:
                context = hunk_match.group(1).strip()
                for pattern in patterns:
                    m = pattern.match(context)
                    if m and m.group(1) not in IGNORE_NAMES:
                        functions.add(m.group(1))
            continue
        
        # Extract function from added/removed/modified lines
        if line.startswith('+') or line.startswith('-'):
            code = line[1:]  # strip +/- prefix
            for pattern in patterns:
                m = pattern.match(code)
                if m and m.group(1) not in IGNORE_NAMES:
                    functions.add(m.group(1))
    
    return functions


# ──────────────────────────────────────────────────────────────
# GitHub Advisory + Commit Mining
# ──────────────────────────────────────────────────────────────

def get_fix_commits_from_advisory(ghsa_id):
    """Fetch a GHSA advisory and extract fix commit URLs."""
    url = f"https://api.github.com/advisories/{ghsa_id}"
    data = fetch_json(url)
    if not data:
        return [], None
    
    commits = []
    references = data.get('references', [])
    
    for ref in references:
        ref_url = ref if isinstance(ref, str) else ref.get('url', '')
        # Match GitHub commit URLs 
        if '/commit/' in ref_url and 'github.com' in ref_url:
            commits.append(ref_url)
        # Match GitHub pull request URLs
        elif '/pull/' in ref_url and 'github.com' in ref_url:
            commits.append(ref_url)
    
    # Also extract the source repository
    source_repo = None
    for ref in references:
        ref_url = ref if isinstance(ref, str) else ref.get('url', '')
        m = re.match(r'https://github\.com/([^/]+/[^/]+)', ref_url)
        if m and 'advisories' not in ref_url and 'nvd.nist' not in ref_url:
            source_repo = m.group(1)
            break
    
    return commits, source_repo


def get_commit_diff(commit_url):
    """Fetch the diff for a GitHub commit."""
    # Convert commit URL to API diff URL
    # https://github.com/owner/repo/commit/sha → API patch
    m = re.match(r'https://github\.com/([^/]+/[^/]+)/commit/([a-f0-9]+)', commit_url)
    if m:
        repo, sha = m.group(1), m.group(2)
        diff_url = f"https://github.com/{repo}/commit/{sha}.diff"
        return fetch_text(diff_url)
    
    # Handle PR URLs
    m = re.match(r'https://github\.com/([^/]+/[^/]+)/pull/(\d+)', commit_url)
    if m:
        repo, pr_num = m.group(1), m.group(2)
        diff_url = f"https://github.com/{repo}/pull/{pr_num}.diff"
        return fetch_text(diff_url)
    
    return None


# ──────────────────────────────────────────────────────────────
# Method Observatory Integration
# ──────────────────────────────────────────────────────────────

def get_package_methods(package_name):
    """Fetch all methods for a package from the Method Observatory."""
    try:
        url = f"{METHOD_OBS_URL}/methods/{package_name}"
        data = fetch_json(url)
        if not data:
            return None
        return data
    except Exception as e:
        print(f"  ⚠ Could not reach Method Observatory: {e}")
        return None


def check_reachability(package_name, function_name):
    """Check if a function is reachable from entry points in the Method Observatory."""
    try:
        url = f"{METHOD_OBS_URL}/methods/{package_name}/reachability/{function_name}"
        data = fetch_json(url)
        if not data:
            return None
        return data
    except Exception:
        return None


def find_method_in_observatory(package_name, func_names, hotspots_by_pkg):
    """Cross-reference mined function names with Method Observatory data.
    
    Returns list of (func_name, found_in_observatory, is_hotspot, composite_risk)
    """
    results = []
    pkg_hotspots = hotspots_by_pkg.get(package_name, [])
    hotspot_names = {h['method_name'] for h in pkg_hotspots}
    hotspot_map = {h['method_name']: h for h in pkg_hotspots}
    
    for func in func_names:
        found = func in hotspot_names
        is_hotspot = False
        composite_risk = 0.0
        rank = None
        is_orphan = False
        
        if found:
            h = hotspot_map[func]
            is_hotspot = True
            composite_risk = float(h.get('composite_risk', 0))
            rank = int(h.get('rank', 0))
            is_orphan = h.get('is_orphan', 'False') == 'True'
        
        results.append({
            'function_name': func,
            'found_in_call_graph': found,
            'is_hotspot': is_hotspot,
            'composite_risk': composite_risk,
            'hotspot_rank': rank,
            'is_orphan': is_orphan,
        })
    
    return results


# ──────────────────────────────────────────────────────────────
# Main Pipeline
# ──────────────────────────────────────────────────────────────

def load_csv(path):
    """Load CSV as list of dicts."""
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def main():
    print("=" * 70)
    print("OSCAR CVE PATCH MINING")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)
    
    # Load data
    vulns = load_csv(VULN_FILE)
    hotspots = load_csv(HOTSPOTS_FILE)
    
    # Index hotspots by package
    hotspots_by_pkg = defaultdict(list)
    for h in hotspots:
        hotspots_by_pkg[h['package']].append(h)
    
    # Deduplicate CVEs by (affected_package, vuln_id)
    seen = set()
    unique_vulns = []
    for v in vulns:
        key = (v['affected_package'], v['vuln_id'])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    
    # Filter to GHSA IDs only (GitHub Advisory API)
    ghsa_vulns = [v for v in unique_vulns if v['vuln_id'].startswith('GHSA-')]
    pysec_vulns = [v for v in unique_vulns if v['vuln_id'].startswith('PYSEC-')]
    
    print(f"\n  Total unique CVEs: {len(unique_vulns)}")
    print(f"  GHSA IDs (minable): {len(ghsa_vulns)}")
    print(f"  PYSEC IDs (skip): {len(pysec_vulns)}")
    
    # Process each GHSA advisory
    all_results = []
    summary_stats = {
        'total_processed': 0,
        'commits_found': 0,
        'functions_extracted': 0,
        'functions_in_call_graph': 0,
        'functions_unreachable': 0,
        'advisories_with_functions': 0,
    }
    
    print(f"\n{'=' * 70}")
    print("MINING FIX COMMITS")
    print(f"{'=' * 70}\n")
    
    for i, vuln in enumerate(ghsa_vulns, 1):
        ghsa_id = vuln['vuln_id']
        pkg = vuln['affected_package']
        eco = vuln['root_ecosystem']
        
        print(f"  [{i}/{len(ghsa_vulns)}] {ghsa_id} ({eco}/{pkg})")
        
        # Step 1: Get fix commits from advisory
        time.sleep(GITHUB_DELAY)  # rate limiting
        commits, source_repo = get_fix_commits_from_advisory(ghsa_id)
        
        if not commits:
            print(f"    → No fix commits found in advisory")
            all_results.append({
                'vuln_id': ghsa_id,
                'affected_package': pkg,
                'ecosystem': eco,
                'severity': vuln.get('severity', ''),
                'fix_commits_found': 0,
                'functions_mined': '',
                'num_functions_mined': 0,
                'functions_in_call_graph': '',
                'num_in_call_graph': 0,
                'reachability_verdicts': '',
                'has_unreachable': False,
                'source_repo': source_repo or '',
            })
            continue
        
        summary_stats['total_processed'] += 1
        summary_stats['commits_found'] += 1
        
        print(f"    → {len(commits)} fix commit(s) found")
        
        # Step 2: Fetch diffs and extract function names
        all_functions = set()
        
        for commit_url in commits[:3]:  # Limit to first 3 commits
            time.sleep(GITHUB_DELAY)
            diff = get_commit_diff(commit_url)
            
            if diff:
                funcs = extract_functions_from_diff(diff, eco)
                all_functions.update(funcs)
                print(f"    → Diff parsed: {len(funcs)} functions found")
            else:
                print(f"    → Could not fetch diff for {commit_url[:60]}...")
        
        if all_functions:
            summary_stats['advisories_with_functions'] += 1
            summary_stats['functions_extracted'] += len(all_functions)
            print(f"    → Total unique functions: {list(all_functions)[:5]}{'...' if len(all_functions) > 5 else ''}")
        
        # Step 3: Cross-reference with Method Observatory
        matched = find_method_in_observatory(pkg, all_functions, hotspots_by_pkg)
        in_cg = [m for m in matched if m['found_in_call_graph']]
        orphans = [m for m in matched if m['is_orphan']]
        
        summary_stats['functions_in_call_graph'] += len(in_cg)
        
        if in_cg:
            print(f"    → {len(in_cg)}/{len(all_functions)} found in call graph")
            for m in in_cg:
                status = "ORPHAN (unreachable)" if m['is_orphan'] else "CONNECTED"
                print(f"      • {m['function_name']} → {status} (risk={m['composite_risk']:.2f})")
        
        if orphans:
            summary_stats['functions_unreachable'] += len(orphans)
        
        # Step 4: Try reachability endpoint (if Method Observatory is running)
        reachability_results = []
        for func_match in in_cg:
            reach = check_reachability(pkg, func_match['function_name'])
            if reach:
                reachability_results.append({
                    'function': func_match['function_name'],
                    'reachable': reach.get('reachable', 'unknown'),
                    'path_length': reach.get('path_length', None),
                })
        
        all_results.append({
            'vuln_id': ghsa_id,
            'affected_package': pkg,
            'ecosystem': eco,
            'severity': vuln.get('severity', ''),
            'fix_commits_found': len(commits),
            'functions_mined': ';'.join(sorted(all_functions)),
            'num_functions_mined': len(all_functions),
            'functions_in_call_graph': ';'.join(m['function_name'] for m in in_cg),
            'num_in_call_graph': len(in_cg),
            'reachability_verdicts': ';'.join(
                f"{r['function']}={'REACHABLE' if r['reachable'] else 'UNREACHABLE'}"
                for r in reachability_results
            ),
            'has_unreachable': any(m['is_orphan'] for m in matched),
            'source_repo': source_repo or '',
        })
    
    # ──────────────────────────────────────────────────────────
    # Save Results
    # ──────────────────────────────────────────────────────────
    
    print(f"\n{'=' * 70}")
    print("RESULTS SUMMARY")
    print(f"{'=' * 70}")
    
    print(f"\n  Advisories processed:         {len(ghsa_vulns)}")
    print(f"  With fix commits:             {summary_stats['commits_found']}")
    print(f"  With mined functions:          {summary_stats['advisories_with_functions']}")
    print(f"  Total functions extracted:     {summary_stats['functions_extracted']}")
    print(f"  Functions found in call graph: {summary_stats['functions_in_call_graph']}")
    print(f"  Functions identified as orphan: {summary_stats['functions_unreachable']}")
    
    # Compute reachability filtering potential
    advisories_with_orphans = sum(1 for r in all_results if r['has_unreachable'])
    advisories_with_functions = sum(1 for r in all_results if r['num_functions_mined'] > 0)
    
    if advisories_with_functions > 0:
        filter_rate = advisories_with_orphans / advisories_with_functions * 100
        print(f"\n  REACHABILITY FILTERING POTENTIAL:")
        print(f"    Advisories with mined functions:     {advisories_with_functions}")
        print(f"    Advisories with unreachable funcs:   {advisories_with_orphans}")
        print(f"    Potential false-positive filter rate: {filter_rate:.1f}%")
    
    # Save CSV
    out_path = DATA_DIR / "cve_patch_analysis.csv"
    if all_results:
        with open(out_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n  → {out_path.name} ({len(all_results)} rows)")
    
    # Also save a detailed JSON for further analysis
    json_path = DATA_DIR / "cve_patch_analysis.json"
    with open(json_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'summary': summary_stats,
            'results': all_results,
        }, f, indent=2, default=str)
    print(f"  → {json_path.name}")
    
    print(f"\n{'=' * 70}")
    print("PATCH MINING COMPLETE")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
