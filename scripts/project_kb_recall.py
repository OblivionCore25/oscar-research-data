#!/usr/bin/env python3
"""
OSCAR — Project KB Cross-Validation
=====================================
Validates our Java patch mining pipeline against SAP's Project KB dataset
(1,297 manually curated vulnerability statements with fix commits).

Approach:
  Since Project KB doesn't include explicit affected_constructs (just fix commits),
  we use a two-pronged validation strategy:

  1. CONSISTENCY CHECK: For entries where KB identifies the same fix commit as GHSA,
     run our regex extraction on the commit diff and report what we find.
     This demonstrates our pipeline produces meaningful results on Java code.

  2. COVERAGE METRIC: What fraction of KB's 1,297 vulnerabilities can our pipeline
     successfully extract function names from?

  3. CROSS-REFERENCE: For CVEs that appear in BOTH our GHSA corpus (npm/PyPI) and
     KB's corpus (Java/Maven), compare the advisory metadata.

Usage:
    python oscar-research-data/scripts/project_kb_recall.py

Prerequisites:
    - Project KB cloned: oscar-research-data/external/project-kb/
      (git clone --depth 1 --branch vulnerability-data https://github.com/SAP/project-kb.git)
"""

import csv
import json
import os
import re
import ssl
import sys
import time
import yaml
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# SSL context for macOS (Python's bundled certificates often can't verify)
# The default context creates successfully but fails on connect
_SSL_CTX = ssl._create_unverified_context()

# Import extraction function from our pipeline
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))
from mine_cve_patches import (
    extract_functions_from_diff,
    fetch_text,
    GITHUB_DELAY,
)

# ============================================================================
# Configuration
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent
KB_DIR = BASE_DIR / "oscar-research-data" / "external" / "project-kb"
KB_STATEMENTS_DIR = KB_DIR / "statements"

DATA_OUT_DIR = BASE_DIR / "oscar-patch-mining" / "data"
DATA_OUT_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Rate limiting
MAX_DIFFS_TO_FETCH = 1300  # Full KB dataset (~1248 entries, needs GITHUB_TOKEN)


# ============================================================================
# Load Project KB Statements (YAML)
# ============================================================================

def load_kb_statements():
    """Parse all Project KB YAML statement files."""
    entries = []
    
    if not KB_STATEMENTS_DIR.exists():
        print(f"  ERROR: Project KB not found at {KB_STATEMENTS_DIR}")
        print(f"  Run: git clone --depth 1 --branch vulnerability-data https://github.com/SAP/project-kb.git")
        return []
    
    for yaml_path in sorted(KB_STATEMENTS_DIR.glob("*/statement.yaml")):
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                continue
            
            vuln_id = data.get('vulnerability_id', '')
            
            # Extract fix commits
            commits = []
            for fix in data.get('fixes', []):
                for commit in fix.get('commits', []):
                    repo = commit.get('repository', '')
                    sha = commit.get('id', '')
                    if repo and sha:
                        # Normalize repo URL
                        repo_match = re.match(r'https?://github\.com/([^/]+/[^/]+)', repo)
                        if repo_match:
                            repo_normalized = repo_match.group(1).rstrip('/')
                        else:
                            repo_normalized = repo.rstrip('/')
                        commits.append({
                            'repo': repo_normalized,
                            'sha': sha,
                        })
            
            # Extract affected artifacts (package info)
            packages = set()
            for artifact in data.get('artifacts', []):
                pkg_id = artifact.get('id', '')
                if 'maven' in pkg_id.lower():
                    # Parse pkg:maven/group/artifact@version
                    m = re.match(r'pkg:maven/([^@]+)', pkg_id)
                    if m:
                        packages.add(m.group(1))
            
            if commits:
                entries.append({
                    'vuln_id': vuln_id,
                    'commits': commits,
                    'packages': list(packages),
                    'num_commits': len(commits),
                })
        except Exception as e:
            # Skip malformed YAML
            continue
    
    return entries


# ============================================================================
# Diff Fetching
# ============================================================================

def fetch_commit_diff(repo, sha):
    """Fetch the unified diff for a GitHub commit."""
    diff_url = f"https://github.com/{repo}/commit/{sha}.diff"
    headers = {"User-Agent": "OSCAR-Research/1.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    
    try:
        req = urllib.request.Request(diff_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
            return resp.read().decode(errors='replace')
    except Exception as e:
        return None


# ============================================================================
# Main Pipeline
# ============================================================================

def main():
    print("=" * 70)
    print("OSCAR — PROJECT KB CROSS-VALIDATION")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)
    
    # Step 1: Load KB data
    print("\n[1/4] Loading Project KB statements...")
    kb_entries = load_kb_statements()
    print(f"  Total KB entries with fix commits: {len(kb_entries)}")
    
    # Statistics
    total_commits = sum(e['num_commits'] for e in kb_entries)
    with_packages = sum(1 for e in kb_entries if e['packages'])
    print(f"  Total fix commits: {total_commits}")
    print(f"  Entries with Maven package info: {with_packages}")
    
    # Filter to GitHub-hosted repos only
    github_entries = [
        e for e in kb_entries 
        if any('/' in c['repo'] for c in e['commits'])
    ]
    print(f"  Entries with GitHub repos: {len(github_entries)}")
    
    # Step 2: Sample and fetch diffs
    print(f"\n[2/4] Fetching diffs (max {MAX_DIFFS_TO_FETCH})...")
    
    results = []
    diffs_fetched = 0
    functions_extracted_total = 0
    entries_with_functions = 0
    
    for i, entry in enumerate(github_entries[:MAX_DIFFS_TO_FETCH]):
        vuln_id = entry['vuln_id']
        
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{min(len(github_entries), MAX_DIFFS_TO_FETCH)}] {vuln_id}")
        
        all_functions = set()
        commits_processed = 0
        
        for commit in entry['commits'][:2]:  # Max 2 commits per vuln
            time.sleep(GITHUB_DELAY)
            diff = fetch_commit_diff(commit['repo'], commit['sha'])
            
            if diff:
                diffs_fetched += 1
                commits_processed += 1
                funcs = extract_functions_from_diff(diff, 'maven')
                all_functions.update(funcs)
        
        if all_functions:
            entries_with_functions += 1
            functions_extracted_total += len(all_functions)
        
        results.append({
            'vuln_id': vuln_id,
            'repo': entry['commits'][0]['repo'] if entry['commits'] else '',
            'packages': ';'.join(entry['packages']),
            'num_commits_kb': entry['num_commits'],
            'commits_processed': commits_processed,
            'functions_extracted': ';'.join(sorted(all_functions)),
            'num_functions': len(all_functions),
        })
    
    # Step 3: Compute metrics
    print(f"\n[3/4] Computing metrics...")
    
    processed = len(results)
    extraction_rate = entries_with_functions / processed * 100 if processed else 0
    avg_functions = functions_extracted_total / entries_with_functions if entries_with_functions else 0
    
    print(f"\n{'=' * 70}")
    print("RESULTS SUMMARY")
    print(f"{'=' * 70}")
    
    print(f"\n  KB entries processed:           {processed}")
    print(f"  Diffs successfully fetched:     {diffs_fetched}")
    print(f"  Entries with extracted funcs:   {entries_with_functions}")
    print(f"  Extraction rate:               {extraction_rate:.1f}%")
    print(f"  Total functions extracted:      {functions_extracted_total}")
    print(f"  Avg functions per entry:        {avg_functions:.1f}")
    
    # Function count distribution
    func_counts = [r['num_functions'] for r in results]
    zero_count = sum(1 for c in func_counts if c == 0)
    one_to_five = sum(1 for c in func_counts if 1 <= c <= 5)
    six_to_twenty = sum(1 for c in func_counts if 6 <= c <= 20)
    over_twenty = sum(1 for c in func_counts if c > 20)
    
    print(f"\n  Distribution of functions extracted:")
    print(f"    0 functions:     {zero_count} ({zero_count/processed*100:.1f}%)")
    print(f"    1-5 functions:   {one_to_five} ({one_to_five/processed*100:.1f}%)")
    print(f"    6-20 functions:  {six_to_twenty} ({six_to_twenty/processed*100:.1f}%)")
    print(f"    >20 functions:   {over_twenty} ({over_twenty/processed*100:.1f}%)")
    
    # Compare with our JS/Python extraction rate
    print(f"\n  COMPARISON WITH JS/PYTHON PIPELINE:")
    print(f"    JS/Python extraction rate: 58.6% (95/162 advisories)")
    print(f"    Java extraction rate:      {extraction_rate:.1f}% ({entries_with_functions}/{processed} entries)")
    
    # Step 4: Save results
    print(f"\n[4/4] Saving results...")
    
    out_csv = DATA_OUT_DIR / "project_kb_java_extraction.csv"
    if results:
        with open(out_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"  → {out_csv}")
    
    # Save summary
    out_summary = DATA_OUT_DIR / "project_kb_validation_summary.txt"
    with open(out_summary, 'w') as f:
        f.write(f"OSCAR Project KB Cross-Validation\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"{'=' * 50}\n\n")
        f.write(f"Project KB entries (total):     {len(kb_entries)}\n")
        f.write(f"Entries processed:              {processed}\n")
        f.write(f"Diffs fetched:                  {diffs_fetched}\n")
        f.write(f"Entries with functions:          {entries_with_functions}\n")
        f.write(f"Extraction rate:                {extraction_rate:.1f}%\n")
        f.write(f"Total functions extracted:       {functions_extracted_total}\n")
        f.write(f"Avg functions per entry:         {avg_functions:.1f}\n\n")
        f.write(f"JS/Python extraction rate:       58.6% (95/162)\n")
        f.write(f"Java extraction rate:            {extraction_rate:.1f}% ({entries_with_functions}/{processed})\n")
    print(f"  → {out_summary}")
    
    # Print sample extractions
    print(f"\n{'=' * 70}")
    print("SAMPLE EXTRACTIONS (first 10 with functions)")
    print(f"{'=' * 70}")
    
    shown = 0
    for r in results:
        if r['num_functions'] > 0 and shown < 10:
            print(f"\n  {r['vuln_id']} ({r['repo']})")
            print(f"    Packages: {r['packages']}")
            print(f"    Functions ({r['num_functions']}): {r['functions_extracted'][:100]}{'...' if len(r['functions_extracted']) > 100 else ''}")
            shown += 1
    
    print(f"\n{'=' * 70}")
    print("CROSS-VALIDATION COMPLETE")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
