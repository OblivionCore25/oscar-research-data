# OSCAR Research Pipeline — Reproducibility Guide

> **Purpose:** This document explains every component, technique, and API endpoint used to generate the empirical data for the ICSE 2027 paper *"Cross-Level Risk Propagation."* It enables any researcher to reproduce the entire pipeline from scratch.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Stage 1: Corpus Definition](#2-stage-1-corpus-definition)
3. [Stage 2: Data Ingestion](#3-stage-2-data-ingestion)
4. [Stage 3: Data Export](#4-stage-3-data-export)
5. [Stage 4: CVE Patch Mining](#5-stage-4-cve-patch-mining)
6. [Stage 5: Experiment Analysis](#6-stage-5-experiment-analysis)
7. [OSCAR API Reference](#7-oscar-api-reference)
8. [Background Techniques](#8-background-techniques)
9. [Reuse Guide](#9-reuse-guide)

---

## 1. Architecture Overview

The research pipeline operates across **three layers**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      EXTERNAL DATA SOURCES                         │
│  npm Registry │ PyPI Registry │ deps.dev │ OSV │ GitHub Advisory API│
└──────┬────────┴──────┬────────┴────┬─────┴──┬──┴────────┬──────────┘
       │               │             │        │           │
       ▼               ▼             ▼        ▼           │
┌──────────────────────────────────────────────────────┐  │
│           OSCAR Platform (Runtime Services)          │  │
│                                                      │  │
│  ┌──────────────────────┐  ┌──────────────────────┐  │  │
│  │ Dependency Observatory│  │  Method Observatory  │  │  │
│  │     (port 8000)       │  │    (port 8001)       │  │  │
│  │                       │  │                      │  │  │
│  │ • Transitive graph    │  │ • AST call graph     │  │  │
│  │ • Ecosystem enrichment│  │ • Composite risk     │  │  │
│  │ • Cross-level analysis│◄─┤ • Reachability       │  │  │
│  │ • Vulnerability scan  │  │ • Git churn analysis │  │  │
│  └──────────────────────┘  └──────────────────────┘  │  │
└──────────────────┬───────────────────┬───────────────┘  │
                   │                   │                   │
                   ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    RESEARCH SCRIPTS (Offline)                       │
│                                                                     │
│  ingest_corpus.py → export_research_data.py → analyze_experiments.py│
│                                                  ↑                  │
│                                    mine_cve_patches.py ─────────────┘
│                                    (GitHub Advisory API)             │
└─────────────────────────────────────────────────────────────────────┘
```

**Key distinction:** OSCAR services provide the *computational engine* (graph resolution, call-graph construction, metric computation). The research scripts provide *orchestration* (batch processing, data marshalling, experiment logic). The patch mining script accesses *external APIs* (GitHub) directly, bypassing OSCAR, then cross-references its results back with OSCAR's call graphs.

---

## 2. Stage 1: Corpus Definition

**File:** [`scripts/corpus.json`](file:///Users/fabiangonzalez/Documents/OSCAR/scripts/corpus.json)

The study corpus is a JSON file listing 50 packages with their ecosystem, name, version, and category:

```json
{
  "packages": [
    {"ecosystem": "npm", "name": "express", "version": "5.1.0", "category": "high-impact"},
    {"ecosystem": "pypi", "name": "requests", "version": "2.32.3", "category": "security-critical"},
    {"ecosystem": "npm", "name": "ms", "version": "2.1.3", "category": "micro-dep"},
    ...
  ]
}
```

### Selection Criteria

Packages were chosen using three archetypes:

| Category | Count | Selection Rationale |
|----------|-------|-------------------|
| `high-impact` | 24 | Large transitive trees (express, flask, django, react) |
| `security-critical` | 15 | Known CVE histories (axios, urllib3, lodash) |
| `micro-dep` | 11 | <50 methods but >50K fan-in (ms, inherits, escape-html) |

### Version Pinning

Versions are pinned to specific releases (not ranges) to ensure reproducibility. Four PyPI packages required version adjustments after the upstream dependency resolver failed on initial versions.

---

## 3. Stage 2: Data Ingestion

**Script:** [`scripts/ingest_corpus.py`](file:///Users/fabiangonzalez/Documents/OSCAR/scripts/ingest_corpus.py)

This script batch-loads all 50 packages into both OSCAR observatories. It performs **four actions per package**:

### 3.1 Dependency Observatory Ingestion

**OSCAR Endpoint:** `GET /packages/{ecosystem}/{name}/{version}`

This is the **auto-ingestion** endpoint. When queried for a package that doesn't exist in the local store, the observatory:

1. Fetches the package metadata from the registry API (npm or PyPI)
2. Resolves all declared dependencies recursively (BFS)
3. Computes graph metrics (PageRank, betweenness centrality, bottleneck score)
4. Persists the full transitive graph in PostgreSQL
5. Returns the package details with computed metrics

**Important design choice:** There is no separate `POST /ingest` endpoint. The GET endpoint triggers ingestion on cache miss, making the system behave as a transparent cache.

### 3.2 Ecosystem Enrichment

**OSCAR Endpoint:** `GET /analytics/enrich/{ecosystem}/{name}/{version}`

After graph resolution, this endpoint enriches each package node with:

| Metric | Source | Technique |
|--------|--------|-----------|
| Global fan-in | [deps.dev API](https://deps.dev) | Queries the pre-computed reverse dependency count |
| OpenSSF Scorecard | [Scorecard API](https://scorecard.dev) | Fetches the security health score |
| Monthly downloads | npm/PyPI registry APIs | Direct registry query |

### 3.3 Method Observatory Ingestion

**OSCAR Endpoint:** `POST /methods/ingest/{ecosystem}/{package_name}`

This endpoint performs the full method-level analysis pipeline:

1. **Source acquisition:** Downloads the published tarball (npm) or sdist/wheel (PyPI) from the registry
2. **AST extraction:** Parses every source file into an abstract syntax tree using Python's `ast` module (for `.py`) or a custom JavaScript parser (for `.js/.mjs`)
3. **Definition extraction:** Extracts all function definitions, class methods, and class definitions with metadata (name, module, line range, parameters)
4. **Call site extraction:** Identifies all function/method invocations with target name and enclosing context
5. **External classification:** Classifies each call site as internal, external (stdlib/dependency), or dynamic using the **definition-existence criterion** (see §8)
6. **Call resolution:** Resolves internal call sites to concrete definitions using a **6-strategy priority chain** (see §8)
7. **Graph construction:** Builds the call graph as an adjacency list and computes all method-level metrics (complexity, centrality, blast radius, composite risk)

Results are cached as JSON on the filesystem — subsequent queries return instantly.

### 3.4 Git Churn Analysis

**OSCAR Endpoint:** `POST /methods/git-profile/{ecosystem}/{package_name}`

This endpoint clones the package's source repository (if a GitHub URL is found in the registry metadata) and computes:

- Total commits, contributors, and bus factor
- Per-file commit frequency in a 6-month window
- Days since last commit
- Temporal factor for each method (churn relative to repo average)

### Running the Ingestion

```bash
# Full ingestion (both observatories)
python scripts/ingest_corpus.py --corpus scripts/corpus.json

# Resume from a specific package (0-indexed)
python scripts/ingest_corpus.py --start-from 25

# Skip already-ingested packages
python scripts/ingest_corpus.py --skip-existing

# Dependency observatory only
python scripts/ingest_corpus.py --skip-method
```

**Timing:** Full ingestion of 50 packages takes ~11 minutes (network-bound).

---

## 4. Stage 3: Data Export

**Script:** [`research/scripts/export_research_data.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/export_research_data.py)

This script queries both observatories and marshals the responses into 5 structured CSV files. It is the **bridge between OSCAR's runtime API and static research data**.

### 4.1 Corpus Summary (`corpus_summary.csv`)

**Endpoints used:**
- `GET /packages/{eco}/{name}/{ver}` → dependency metrics (fan-in, bottleneck, libyears, graph topology)
- `GET /methods/{slug}` → method observatory metadata (method count, resolution rate, LOC)

**Output:** 50 rows × 26 columns — one row per package with both ecosystem and method-level metrics.

### 4.2 Cross-Level Results (`cross_level_results.csv`)

**Endpoint used:**
- `GET /analytics/{eco}/{name}/{ver}/cross-level?top_n=10`

This is the **most important endpoint** in the pipeline. It orchestrates the cross-level analysis:

1. Resolves the transitive dependency graph for the root package
2. Ranks dependencies by bottleneck score (PageRank + betweenness centrality)
3. For the top-N dependencies, calls the Method Observatory to get method hotspots
4. Computes cross-level risk = composite_risk × log₁₀(fan_in + 1)
5. Returns a unified ranking of the riskiest methods across the supply chain

**Computation performed by the export script (not OSCAR):** The four formula variants (`cl_risk_log10`, `cl_risk_log2`, `cl_risk_sqrt`, `cl_risk_linear`) are computed client-side from the raw composite risk and fan-in values. This ensures formula comparisons use identical underlying data.

**Output:** 825 rows × 24 columns — one row per method-risk entry.

### 4.3 Vulnerability Results (`vulnerability_results.csv`)

**Endpoints used:**
- `GET /dependencies/{eco}/{name}/{ver}/vulnerabilities` → CVEs from OSV database
- `GET /reachability/{slug}?functions=...` → reachability verdicts (if affected functions are available)

**Output:** 73 rows × 17 columns — one row per CVE-package pair, including severity and reachability status.

### 4.4 Method Hotspots (`method_hotspots.csv`)

**Endpoint used:**
- `GET /methods/{slug}/hotspots?limit=20` → top-20 method hotspots per package

**Output:** 761 rows × 26 columns — structural properties of each hotspot method (complexity, centrality, blast radius, orphan status, composite risk, temporal factor).

### 4.5 Temporal Profiles (`temporal_profiles.csv`)

**Endpoint used:**
- `GET /methods/{slug}/git-profile` → git churn data

**Output:** 50 rows × 12 columns — package-level git health metrics.

### Running the Export

```bash
# Full export (all 5 datasets)
python research/scripts/export_research_data.py \
    --corpus scripts/corpus.json \
    --output-dir research/data

# Single dataset only
python research/scripts/export_research_data.py --only cross_level
```

---

## 5. Stage 4: CVE Patch Mining

**Script:** [`research/scripts/mine_cve_patches.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/mine_cve_patches.py)

This is the **novel technique** developed to address the OSV data gap. It operates **independently of OSCAR** for data acquisition, then **cross-references with OSCAR** for reachability analysis.

### 5.1 The Problem

The OSV advisory database includes an `affected_functions` field in its schema, but it is populated for **0% of the 56 CVEs** in our corpus. Without knowing which functions are affected, reachability analysis cannot determine whether a CVE is a false positive.

### 5.2 The Technique

The patch mining pipeline has 4 stages:

#### Stage A: Advisory Fetch

```
GHSA-xxxx-yyyy-zzzz → GitHub Advisory API → advisory metadata
```

**API:** `GET https://api.github.com/advisories/{GHSA-ID}`

The advisory JSON contains a `references[]` array with URLs. We extract:
- **Fix commit URLs** matching the pattern: `https://github.com/{owner}/{repo}/commit/{sha}`
- **Pull request URLs** matching: `https://github.com/{owner}/{repo}/pull/{number}`
- The source repository name (for logging)

**Rate limiting:** GitHub's unauthenticated API allows 60 requests/hour. The script inserts a 2-second delay between requests. Can be increased with a GitHub personal access token.

#### Stage B: Diff Acquisition

```
commit URL → GitHub .diff endpoint → unified diff text
```

We convert the commit URL to a `.diff` URL:
- `https://github.com/owner/repo/commit/sha` → `https://github.com/owner/repo/commit/sha.diff`
- `https://github.com/owner/repo/pull/N` → `https://github.com/owner/repo/pull/N.diff`

The `.diff` endpoint returns the raw unified diff without requiring API authentication.

#### Stage C: Function Extraction from Diffs

This is the core algorithmic contribution. We parse the unified diff to identify which functions were modified, added, or deleted in the fix commit.

**Two extraction strategies are used simultaneously:**

**Strategy 1: Diff hunk headers.** Git's unified diff format includes context in the `@@` header:
```diff
@@ -42,7 +42,9 @@ def parseObject(chain, val, options, valuesParsed):
```
The text after `@@` is the enclosing function/class name. We apply language-specific regex patterns to extract `parseObject` from this context line.

**Strategy 2: Modified lines.** Lines prefixed with `+` or `-` that contain function definitions:
```diff
+def sanitize_header(value):
-def old_parse_method(data):
```

**Language-aware patterns:**

| Language | Patterns Detected |
|----------|------------------|
| **Python** | `def name(`, `async def name(`, `class Name(` |
| **JavaScript** | `function name(`, `const name = function(`, `const name = () =>`, `name() {`, `exports.name =`, `module.exports.name =` |

**Filtering:**
- **Test files** are excluded via path patterns (`test/`, `__tests__/`, `*.test.js`, `*_test.py`, `spec/`)
- **Language keywords** are excluded (`if`, `for`, `while`, `return`, etc.)
- Duplicate function names across multiple diffs for the same advisory are deduplicated

**Yield:** 69% of advisories (31/45) produce at least one function name. Total: 133 unique functions.

#### Stage D: Call Graph Cross-Reference

The mined function names are matched against the Method Observatory's hotspot data:

```
mined function name → hotspots_by_pkg[package] → match by method_name
```

For each matched function, we extract:
- `is_orphan`: Whether the function has no callers (unreachable from entry points)
- `composite_risk`: The function's internal risk score
- `hotspot_rank`: Its position in the package's risk ranking

**Current limitation:** We match against the top-20 hotspots per package (the exported subset). Functions that exist in the full call graph but aren't in the top-20 will appear as "unmatched." This can be resolved by querying the full graph endpoint (`GET /methods/{slug}/graph`).

### 5.3 Output

| File | Content |
|------|---------|
| `cve_patch_analysis.csv` | 45 rows — per-advisory mining results |
| `cve_patch_analysis.json` | Full structured output with summary statistics |

### 5.4 Reuse as a Standalone Tool

The patch mining pipeline is **decoupled from OSCAR** at stages A-C. It could be extracted into a standalone tool:

```python
# Standalone usage (no OSCAR required)
from mine_cve_patches import get_fix_commits_from_advisory, get_commit_diff, extract_functions_from_diff

commits, repo = get_fix_commits_from_advisory("GHSA-6rw7-vpxm-498p")
diff = get_commit_diff(commits[0])
functions = extract_functions_from_diff(diff, ecosystem="npm")
# → {'parseObject'}
```

This could serve the broader SCA community as a **GHSA-to-functions enrichment service**, populating the empty `affected_functions` field in OSV advisories.

---

## 6. Stage 5: Experiment Analysis

**Script:** [`research/scripts/analyze_experiments.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/analyze_experiments.py)

This script operates **entirely offline** — it reads the exported CSVs and produces the statistical results for the paper. No OSCAR services are needed.

### 6.1 RQ1: Ranking Effectiveness

**Input:** `cross_level_results.csv` + `vulnerability_results.csv`

**Method:**
1. Build a set of (root_package → vulnerable_dependency) pairs from the vulnerability data
2. For each root package with CVEs, rank all analyzed methods by three strategies:
   - **Cross-level:** sort by `cross_level_risk` (descending)
   - **Method-only:** sort by `method_composite_risk` (descending)
   - **Ecosystem-only:** sort by `ecosystem_fan_in` (descending)
3. Compute **Precision@K** = (methods from vulnerable deps in top-K) / K
4. Compute **nDCG@K** using binary relevance (1 if from vulnerable dep, 0 otherwise)

### 6.2 RQ2: Reachability Analysis

**Input:** `vulnerability_results.csv` + `method_hotspots.csv` + `cve_patch_analysis.csv`

**Method:**
1. Count CVEs with/without `affected_functions` in OSV
2. For packages with call graphs, analyze orphan method rates
3. Cross-reference patch-mined functions with call graph status
4. Report reachability verdicts for matched functions

### 6.3 RQ3: Formula Sensitivity

**Input:** `cross_level_results.csv` (columns: `cl_risk_log10`, `cl_risk_log2`, `cl_risk_sqrt`, `cl_risk_linear`)

**Method:**
1. Compute **Spearman rank correlation** between all pairs of formula variants
2. For each root package, compute **Jaccard similarity** of the top-3 methods across variants
3. Report distributional statistics (mean, median, std) for score interpretability comparison

### Running the Analysis

```bash
python research/scripts/analyze_experiments.py
```

**Output:**
- `rq1_results.csv` — per-root-package precision scores
- `rq3_results.csv` — per-root-package Jaccard agreement
- `experiment_summary.txt` — all numbers formatted for copy-paste into §5

---

## 7. OSCAR API Reference

### Dependency Observatory (port 8000)

| Method | Endpoint | Used By | Purpose |
|--------|----------|---------|---------|
| `GET` | `/packages/{eco}/{name}/{ver}` | ingest, export | Auto-ingest + fetch package details with metrics |
| `GET` | `/packages?ecosystem=&q=&limit=` | ingest | List packages (no ingestion trigger) |
| `GET` | `/analytics/enrich/{eco}/{name}/{ver}` | ingest | Fetch global fan-in, scorecard from deps.dev |
| `GET` | `/analytics/{eco}/{name}/{ver}/cross-level?top_n=N` | export | **Core:** Cross-level risk analysis |
| `GET` | `/dependencies/{eco}/{name}/{ver}/vulnerabilities` | export | CVE scan via OSV |
| `GET` | `/health` | ingest, export | Health check |

### Method Observatory (port 8001)

| Method | Endpoint | Used By | Purpose |
|--------|----------|---------|---------|
| `POST` | `/methods/ingest/{eco}/{name}` | ingest | Trigger AST analysis + call graph construction |
| `POST` | `/methods/git-profile/{eco}/{name}` | ingest | Trigger git churn analysis |
| `GET` | `/methods/projects` | ingest, export | List all analyzed projects |
| `GET` | `/methods/{slug}` | export | Get project metadata (method count, resolution rate) |
| `GET` | `/methods/{slug}/hotspots?limit=N` | export, patch mining | Top-N method hotspots with full metrics |
| `GET` | `/methods/{slug}/git-profile` | export | Git churn metrics |
| `GET` | `/methods/{slug}/orphans` | — | Orphan methods (no callers) |
| `GET` | `/methods/{slug}/graph` | — | Full call graph (adjacency list) |
| `GET` | `/reachability/{slug}?functions=...` | export | Reachability verdicts for named functions |

### External APIs (used by the patch mining script — not OSCAR)

| API | Endpoint | Purpose |
|-----|----------|---------|
| GitHub Advisory | `GET /advisories/{GHSA-ID}` | Fetch advisory metadata + fix commit refs |
| GitHub Diff | `GET /{owner}/{repo}/commit/{sha}.diff` | Raw unified diff of a commit |
| GitHub PR Diff | `GET /{owner}/{repo}/pull/{N}.diff` | Raw unified diff of a pull request |

---

## 8. Background Techniques

### 8.1 Definition-Existence Criterion (External Classification)

The Method Observatory classifies call sites as "external" using a simple but effective rule:

> A call to function `f` is external if and only if **zero definitions** named `f` exist in the project's symbol table.

This is the catch-all mechanism after four more specific checks (language builtins, stdlib patterns, declared dependency imports, dynamic dispatch markers). It is methodologically consistent with PyCG, which excludes cross-boundary edges from its evaluation scope.

### 8.2 Call Resolution Strategy Chain

Internal call sites are resolved using a **priority-ordered 6-strategy chain**:

1. **Direct match** — same-module function with identical name
2. **Self-call** — `self.method()` resolved via class hierarchy (MRO)
3. **Super-call** — `super().method()` resolved to parent class
4. **Constructor** — `ClassName()` mapped to `__init__`
5. **Module-call** — import alias resolution across modules
6. **Unique-name** — if exactly one definition matches the name project-wide

### 8.3 Cross-Level Risk Formula

The formula bridges two abstraction levels:

```
CLR(method m, dependency Pᵢ) = CompositeRisk(m) × log₁₀(FanIn(Pᵢ) + 1)
```

Where **CompositeRisk** combines four intra-package metrics:

```
CompositeRisk(m) = Complexity(m) × Centrality(m) × BlastRadius(m) × TemporalFactor(m)
```

The log₁₀ dampening compresses fan-in values spanning 6 orders of magnitude (1 to 1.19M) into a manageable ~6x multiplier range.

### 8.4 Resolution Rate Confidence Gate

Reachability verdicts are only issued when the call graph's internal resolution rate R ≥ 0.85:

```
R = |resolved internal calls| / |total internal calls|
```

Below this threshold, the verdict is `UNKNOWN`, preventing unreliable claims from low-quality call graphs.

### 8.5 Patch Mining Diff Parsing

The diff parser exploits two features of Git's unified diff format:

1. **Hunk headers** (`@@ ... @@ context`) — Git includes the name of the enclosing function/class in the hunk header. This captures the *enclosing context* of the modification, even if the function definition itself wasn't modified.

2. **Added/removed lines** (`+`/`-` prefixed) — Lines that match function definition patterns indicate functions that were created, deleted, or had their signature modified.

The combination captures both "where the fix was applied" (hunk context) and "what code was changed" (modified definitions).

---

## 9. Reuse Guide

### Reproducing the Exact Paper Results

```bash
# Prerequisites: Python 3.11+, PostgreSQL, npm & pip
# Start both OSCAR services
cd oscar-dependency-observatory && uvicorn app.main:app --port 8000 &
cd oscar-method-observatory && uvicorn app.main:app --port 8001 &

# Stage 1: Ingest corpus
python scripts/ingest_corpus.py --corpus scripts/corpus.json

# Stage 2: Export datasets
python research/scripts/export_research_data.py \
    --corpus scripts/corpus.json \
    --output-dir research/data

# Stage 3: Mine CVE patches (requires internet for GitHub API)
python research/scripts/mine_cve_patches.py

# Stage 4: Analyze experiments (offline)
python research/scripts/analyze_experiments.py
```

### Using Patch Mining for Other Projects

The patch mining pipeline works for **any GHSA advisory**, not just packages in our corpus:

```python
# Extract affected functions from any GHSA advisory
python -c "
from research.scripts.mine_cve_patches import *
commits, repo = get_fix_commits_from_advisory('GHSA-xxxx-yyyy-zzzz')
for url in commits:
    diff = get_commit_diff(url)
    if diff:
        funcs = extract_functions_from_diff(diff, 'npm')  # or 'pypi'
        print(f'Affected functions: {funcs}')
"
```

### Extending the Corpus

To add new packages:

1. Add entries to `scripts/corpus.json`
2. Re-run `ingest_corpus.py --skip-existing` (only ingests new packages)
3. Re-run `export_research_data.py` (regenerates all CSVs)
4. Re-run `analyze_experiments.py` (recomputes all statistics)

### Adapting for Other Research Questions

The exported CSVs are designed for reuse. Potential extensions:

- **Cross-package reachability:** Use `GET /methods/{slug}/graph` to get full call graphs, compose them across dependencies
- **Longitudinal analysis:** Ingest multiple versions of the same package, compare temporal profiles
- **Ecosystem comparison:** Add Go/Rust packages once OSCAR adds language support
- **CVE prioritization model:** Use the cross-level results + vulnerability data as training data for ML-based prioritization

---

## File Inventory

| File | Purpose | Lines |
|------|---------|-------|
| [`scripts/corpus.json`](file:///Users/fabiangonzalez/Documents/OSCAR/scripts/corpus.json) | Study corpus definition | — |
| [`scripts/ingest_corpus.py`](file:///Users/fabiangonzalez/Documents/OSCAR/scripts/ingest_corpus.py) | Batch ingestion orchestrator | 323 |
| [`research/scripts/export_research_data.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/export_research_data.py) | OSCAR → CSV data export | 500 |
| [`research/scripts/mine_cve_patches.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/mine_cve_patches.py) | CVE patch mining pipeline | 519 |
| [`research/scripts/analyze_experiments.py`](file:///Users/fabiangonzalez/Documents/OSCAR/research/scripts/analyze_experiments.py) | Statistical analysis (P@K, nDCG, Spearman) | ~400 |
| [`research/data/corpus_summary_*.csv`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | 50 rows × 26 cols | — |
| [`research/data/cross_level_results_*.csv`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | 825 rows × 24 cols | — |
| [`research/data/vulnerability_results_*.csv`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | 73 rows × 17 cols | — |
| [`research/data/method_hotspots_*.csv`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | 761 rows × 26 cols | — |
| [`research/data/cve_patch_analysis.csv`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | 45 rows — CVE patch mining results | — |
| [`research/data/experiment_summary.txt`](file:///Users/fabiangonzalez/Documents/OSCAR/research/data) | All numbers for §5 | — |
