# How to Upload to Overleaf

## Quick Start

1. Go to [overleaf.com](https://www.overleaf.com) → **New Project** → **Upload Project**
2. Zip the `paper/` folder:
   ```bash
   cd /Users/fabiangonzalez/Documents/OSCAR/research
   zip -r oscar-paper.zip paper/
   ```
3. Upload `oscar-paper.zip` to Overleaf
4. It will compile immediately using IEEE conference format

## Files

| File | Description |
|------|-------------|
| `main.tex` | Complete paper with §3 and §4 fully drafted |
| `references.bib` | 16 references covering SCA, call graphs, supply chains |

## Section Status

| Section | Status | Est. Pages |
|---------|--------|-----------|
| **§1 Introduction** | **✅ Complete draft** | **1.0** |
| **§2 Related Work** | **✅ Complete draft** | **1.5** |
| **§3 Approach** | **✅ Complete draft** | **1.5** |
| **§4 Framework** | **✅ Complete draft** | **2.0** |
| §5 Evaluation | 🟡 RQ structure + table shells | 2.0 |
| **§6 Discussion** | **✅ Complete draft** | **1.5** |
| §7 Conclusion | 🔴 TODO placeholder | 0.5 |

> **Authorship model changed:** You are the primary author for all sections.
> Collaborator will receive the draft for review/feedback contributions only.

## What's Drafted in §3

- **Threat model** — formal definition of the problem
- **Composite risk formula** — all 4 components (complexity, centrality, blast radius, temporal) with equations
- **Cross-level risk formula** — Eq. 4 (boxed, highlighted) with justification for log₁₀ dampening
- **Formula variants** — all 4 parameterizations for RQ3
- **Internal resolution rate** — formal definition with call-site partitioning and definition-existence criterion
- **Reachability filtering** — formal BFS-based reachability with verdict classes

## What's Drafted in §4

- **Architecture overview** — 3-tier design (Dependency Observatory, Method Observatory, Frontend)
- **Algorithm 1** — Transitive dependency resolution (BFS)
- **Ecosystem enrichment** — fan-in, bottleneck, scorecards, libyears
- **Call graph construction** — 4-stage pipeline (acquisition → AST → classification → resolution)
- **Algorithm 2** — Cross-level risk analysis (the core orchestration)
- **Vulnerability reachability engine** — integration with OSV
- **Implementation details** — tech stack, LOC counts

## TODO markers

Search for `\todo{...}` in `main.tex` to find all placeholders that need data or content.

## Sharing with Collaborator

After uploading, share the Overleaf project with your PhD student so they can begin §2 (Related Work) directly online.
