# OSCAR Research Data

> **Replication Package for:** *Cross-Level Risk Propagation: Bridging Method-Level Architecture with Ecosystem-Level Dependency Analysis*

This repository contains the study corpus, analysis scripts, exported datasets, and methodology documentation for reproducing the empirical evaluation presented in the paper.

---

## Paper Citation

```bibtex
@inproceedings{gonzalez2027crosslevel,
  author    = {Author, Anonymous and {Collaborator}},
  title     = {Cross-Level Risk Propagation: Bridging Method-Level 
               Architecture with Ecosystem-Level Dependency Analysis},
  booktitle = {Proc. 49th IEEE/ACM International Conference on 
               Software Engineering (ICSE)},
  year      = {2027},
  note      = {To appear}
}
```

---

## OSCAR Platform Repositories

The OSCAR (Open Supply-Chain Assurance & Resilience) platform consists of three independently deployable services:

| Repository | Description |
|-----------|-------------|
| [oscar-dependency-observatory](https://github.com/ANONYMIZED_AUTHOR/oscar-dependency-observatory) | Ecosystem-level dependency graph resolution, enrichment, and cross-level orchestration (Python/FastAPI) |
| [oscar-method-observatory](https://github.com/ANONYMIZED_AUTHOR/oscar-method-observatory) | Method-level static call-graph construction, composite risk, and reachability analysis (Python/FastAPI) |
| [oscar-frontend](https://github.com/ANONYMIZED_AUTHOR/oscar-frontend) | Interactive cross-level risk dashboard (TypeScript/React) |

---

## Repository Structure

```
oscar-research-data/
├── corpus/
│   └── corpus.json                    # 50-package study corpus definition
│
├── scripts/
│   ├── ingest_corpus.py               # Step 1: Ingest packages into observatories
│   ├── export_research_data.py        # Step 2: Export analysis data as CSV
│   ├── mine_cve_patches.py            # Step 3: Automated CVE patch mining
│   ├── analyze_experiments.py         # Step 4: Compute RQ1/RQ2/RQ3 results
│   └── verify_patch_mining.py         # Step 5: Spot-check validation (84% precision)
│
├── data/
│   ├── corpus_summary.csv             # Table 1: Corpus summary statistics
│   ├── cross_level_results.csv        # 825 cross-level method-risk entries
│   ├── method_hotspots.csv            # Per-package top-20 highest-risk methods
│   ├── vulnerability_results.csv      # CVE data per package (OSV-sourced)
│   ├── temporal_profiles.csv          # Git-based temporal metrics per package
│   ├── cve_patch_analysis.csv         # Patch mining results (Table 3)
│   ├── cve_patch_analysis.json        # Detailed patch mining output (JSON)
│   ├── rq1_results.csv               # P@K and nDCG values (Table 2)
│   ├── rq3_results.csv               # Spearman ρ and Jaccard similarity (Table 4)
│   └── experiment_summary.txt         # Human-readable results summary
│
├── methodology/
│   ├── reproducibility-guide.md       # End-to-end reproduction instructions
│   ├── patch-mining-technique.md      # Technical deep-dive: automated patch mining
│   └── resolution-rate-methodology.md # Formal definition of resolution rate metric
│
└── paper/
    ├── main.tex                       # Paper source (LaTeX, IEEEtran format)
    ├── references.bib                 # Bibliography (19 references)
    └── OVERLEAF_GUIDE.md              # Overleaf compilation instructions
```

---

## Reproduction Guide

### Prerequisites

- Python 3.11+
- Running instances of both OSCAR observatories (see platform repos above)
- PostgreSQL database (or SQLite for local testing)
- GitHub API access (for patch mining; a personal access token is recommended)

### Steps

```bash
# 1. Ingest the study corpus into both observatories
python3 scripts/ingest_corpus.py

# 2. Export analysis data as CSV
python3 scripts/export_research_data.py

# 3. Mine CVE patches from GitHub advisories
python3 scripts/mine_cve_patches.py

# 4. Compute all RQ results (Tables 2, 3, 4)
python3 scripts/analyze_experiments.py

# 5. Validate patch mining precision (optional)
python3 scripts/verify_patch_mining.py
```

> **Note:** Steps 1–2 require running OSCAR observatory instances. Steps 3–5 can be run offline against the pre-exported data in `data/`.

For detailed instructions, see [`methodology/reproducibility-guide.md`](methodology/reproducibility-guide.md).

---

## Data File Descriptions

### `corpus_summary.csv`
Per-package summary with ecosystem, version, method count, resolution rate, LOC, and CVE count. Source data for **Table 1** in the paper.

### `cross_level_results.csv`
825 method-level entries with composite risk score, fan-in, and cross-level risk (CLR) for each method across the corpus. Source data for **RQ1** and **RQ3**.

### `method_hotspots.csv`
Top-20 highest-risk methods per package, including complexity, centrality, blast radius, and temporal factor sub-scores.

### `vulnerability_results.csv`
CVE data per package sourced from OSV, including severity, affected version ranges, and advisory IDs.

### `cve_patch_analysis.csv`
Results of the automated patch mining pipeline: for each GHSA advisory, the fix commits found, functions mined from diffs, and match status against the call graph. Source data for **Table 3** (RQ2).

### `rq1_results.csv`
Precision@K and nDCG@K values for cross-level, method-only, and ecosystem-only baselines across 10 root packages. Source data for **Table 2**.

### `rq3_results.csv`
Pairwise Spearman rank correlation and top-3 Jaccard similarity across four dampening function variants. Source data for **Table 4**.

---

## Research Questions

| RQ | Question | Key Finding |
|----|----------|-------------|
| **RQ1** | How effective is cross-level risk scoring vs. single-level approaches? | Cross-level doubles ecosystem-only precision (P@5=0.44 vs 0.20) |
| **RQ2** | Can function-level CVE data be automatically recovered for reachability analysis? | 69% of advisories yield function names; 84% mining precision validated |
| **RQ3** | How sensitive is the ranking to the dampening function? | Remarkably stable: Spearman ρ ≥ 0.97 across all variants |

---

## License

This research data is released under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). The OSCAR platform source code is available under its respective licenses in the platform repositories linked above.
