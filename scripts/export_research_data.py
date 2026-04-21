#!/usr/bin/env python3
"""
OSCAR Research Data Export Script

Calls both OSCAR observatories and produces structured CSV files
for academic analysis. Designed for the cross-level risk propagation study.

Usage:
    python export_research_data.py [--output-dir ./research_data] [--dep-url http://127.0.0.1:8000] [--method-url http://127.0.0.1:8001]

Produces:
    corpus_summary.csv         — Per-package metadata and structural metrics
    cross_level_results.csv    — All cross-level risk method scores
    vulnerability_results.csv  — CVEs with affected functions and reachability
    method_hotspots.csv        — Top-20 method hotspots per package
    temporal_profiles.csv      — Version timeline and git churn data

Prerequisites:
    pip install httpx pandas
    Both OSCAR services running on ports 8000 and 8001
"""

import argparse
import csv
import json
import logging
import math
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oscar-export")

DEFAULT_DEP_URL = "http://127.0.0.1:8000"
DEFAULT_METHOD_URL = "http://127.0.0.1:8001"
TIMEOUT = httpx.Timeout(60.0, connect=10.0)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def safe_get(client: httpx.Client, url: str, params: dict = None) -> dict | None:
    """GET with error handling. Returns None on failure."""
    try:
        r = client.get(url, params=params or {})
        if r.status_code == 200:
            return r.json()
        logger.warning(f"  HTTP {r.status_code} from {url}")
        return None
    except httpx.TimeoutException:
        logger.warning(f"  Timeout: {url}")
        return None
    except Exception as e:
        logger.warning(f"  Error: {url} — {e}")
        return None


def normalize_slug(package_name: str, ecosystem: str) -> str:
    """Match the method observatory slug normalization."""
    slug = package_name.replace("@", "").replace("/", "__")
    if ecosystem.lower() == "pypi":
        slug = slug.lower()
    return slug


# ─── Export Functions ─────────────────────────────────────────────────────────

def export_corpus_summary(
    packages: list[dict], dep_client: httpx.Client, method_client: httpx.Client
) -> pd.DataFrame:
    """
    Export 1: corpus_summary.csv
    One row per package with structural metrics from both observatories.
    """
    rows = []
    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        version = pkg["version"]
        category = pkg.get("category", "")
        slug = normalize_slug(name, eco)

        logger.info(f"[{i}/{len(packages)}] {eco}/{name}@{version}")

        row = {
            "ecosystem": eco,
            "package": name,
            "version": version,
            "category": category,
        }

        # ── Dependency Observatory metrics ──
        pkg_data = safe_get(dep_client, f"/packages/{eco}/{name}/{version}")
        if pkg_data:
            metrics = pkg_data.get("metrics", {})
            row.update({
                "direct_dependencies": metrics.get("directDependencies", 0),
                "fan_in_local": metrics.get("fanIn", 0),
                "fan_out": metrics.get("fanOut", 0),
                "bottleneck_score": metrics.get("bottleneckScore", 0.0),
                "page_rank": metrics.get("pageRank", 0.0),
                "betweenness_centrality": metrics.get("betweennessCentrality", 0.0),
                "eigenvector_centrality": metrics.get("eigenvectorCentrality", 0.0),
                "blast_radius_pkg": metrics.get("blastRadius", 0),
                "libyears": metrics.get("libyears", 0.0),
                "transitive_depth": metrics.get("transitiveDepth", 0),
                "diamond_count": metrics.get("diamondCount", 0),
                "global_fan_in": metrics.get("globalFanIn"),
                "monthly_downloads": metrics.get("monthlyDownloads"),
                "scorecard_score": metrics.get("scorecardScore"),
            })

        # ── Method Observatory metadata ──
        meta = safe_get(method_client, f"/methods/{slug}")
        if meta:
            row.update({
                "method_count": meta.get("method_count", 0),
                "class_count": meta.get("class_count", 0),
                "module_count": meta.get("module_count", 0),
                "edge_count": meta.get("edge_count", 0),
                "resolution_rate": meta.get("resolution_rate", 0.0),
                "total_loc": meta.get("total_loc", 0),
                "file_count": meta.get("file_count", 0),
                "is_bundled": meta.get("is_bundled", False),
            })
        else:
            row.update({
                "method_count": None, "class_count": None, "module_count": None,
                "edge_count": None, "resolution_rate": None, "total_loc": None,
                "file_count": None, "is_bundled": None,
            })

        rows.append(row)
        time.sleep(0.1)  # gentle rate limiting

    return pd.DataFrame(rows)


def export_cross_level_results(
    packages: list[dict], dep_client: httpx.Client
) -> pd.DataFrame:
    """
    Export 2: cross_level_results.csv
    All cross-level risk method scores for packages with transitive deps.
    """
    rows = []
    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        version = pkg["version"]

        logger.info(f"[{i}/{len(packages)}] Cross-level: {eco}/{name}@{version}")

        data = safe_get(
            dep_client,
            f"/analytics/{eco}/{name}/{version}/cross-level",
            params={"top_n": 10},
        )
        if not data:
            continue

        for method in data.get("top_risks", []):
            rows.append({
                "root_package": name,
                "root_version": version,
                "root_ecosystem": eco,
                "analyzed_deps": data.get("analyzed_deps", 0),
                "total_deps": data.get("total_deps", 0),
                "coverage_pct": data.get("analysis_coverage_pct", 0.0),
                # Method identity
                "method_name": method.get("method_name", ""),
                "method_module": method.get("method_module", ""),
                "method_qualified_name": method.get("method_qualified_name", ""),
                "dependency_package": method.get("dependency_package", ""),
                "dependency_version": method.get("dependency_version", ""),
                "dependency_ecosystem": method.get("dependency_ecosystem", ""),
                # Method-level metrics
                "complexity": method.get("complexity", 0),
                "method_blast_radius": method.get("method_blast_radius", 0),
                "method_centrality": method.get("method_centrality", 0.0),
                "change_frequency": method.get("change_frequency", 0),
                "method_composite_risk": method.get("method_composite_risk", 0.0),
                # Ecosystem-level metrics
                "ecosystem_fan_in": method.get("ecosystem_fan_in", 0),
                "bottleneck_score": method.get("bottleneck_score", 0.0),
                # Cross-level synthesis
                "cross_level_risk": method.get("cross_level_risk", 0.0),
                # Formula variants for RQ3
                "cl_risk_log10": method.get("method_composite_risk", 0.0) * math.log10(method.get("ecosystem_fan_in", 0) + 1),
                "cl_risk_log2": method.get("method_composite_risk", 0.0) * math.log2(method.get("ecosystem_fan_in", 0) + 1),
                "cl_risk_sqrt": method.get("method_composite_risk", 0.0) * math.sqrt(method.get("ecosystem_fan_in", 0)),
                "cl_risk_linear": method.get("method_composite_risk", 0.0) * method.get("ecosystem_fan_in", 0),
            })

    return pd.DataFrame(rows)


def export_vulnerability_results(
    packages: list[dict], dep_client: httpx.Client, method_client: httpx.Client
) -> pd.DataFrame:
    """
    Export 3: vulnerability_results.csv
    CVEs with affected functions and reachability verdicts.
    """
    rows = []
    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        version = pkg["version"]

        logger.info(f"[{i}/{len(packages)}] Vulns: {eco}/{name}@{version}")

        vuln_data = safe_get(
            dep_client,
            f"/dependencies/{eco}/{name}/{version}/vulnerabilities",
        )
        if not vuln_data or not vuln_data.get("breakdown"):
            continue

        for pkg_ver, vulns in vuln_data["breakdown"].items():
            dep_name = pkg_ver.rsplit("@", 1)[0] if "@" in pkg_ver else pkg_ver
            dep_version = pkg_ver.rsplit("@", 1)[1] if "@" in pkg_ver else ""
            dep_slug = normalize_slug(dep_name, eco)

            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                severity = vuln.get("severity", "UNKNOWN")
                affected_funcs = vuln.get("affectedFunctions", [])

                base_row = {
                    "root_package": name,
                    "root_version": version,
                    "root_ecosystem": eco,
                    "affected_package": dep_name,
                    "affected_version": dep_version,
                    "vuln_id": vuln_id,
                    "severity": severity,
                    "summary": vuln.get("summary", ""),
                    "published": vuln.get("published", ""),
                    "has_affected_functions": len(affected_funcs) > 0,
                    "affected_functions": ",".join(affected_funcs),
                }

                if affected_funcs:
                    # Try reachability analysis
                    reach_data = safe_get(
                        method_client,
                        f"/reachability/{dep_slug}",
                        params={"functions": ",".join(affected_funcs)},
                    )
                    if reach_data:
                        for result in reach_data.get("results", []):
                            rows.append({
                                **base_row,
                                "function_name": result.get("function", ""),
                                "reachability_status": result.get("status", "UNKNOWN"),
                                "reachability_reason": result.get("reason", ""),
                                "reachability_path_length": len(result.get("path", [])),
                                "entry_points_found": reach_data.get("entry_points_found", 0),
                                "dep_resolution_rate": reach_data.get("resolution_rate", 0.0),
                            })
                    else:
                        for func in affected_funcs:
                            rows.append({
                                **base_row,
                                "function_name": func,
                                "reachability_status": "NOT_ANALYZED",
                                "reachability_reason": "Method observatory data unavailable",
                                "reachability_path_length": None,
                                "entry_points_found": None,
                                "dep_resolution_rate": None,
                            })
                else:
                    rows.append({
                        **base_row,
                        "function_name": "",
                        "reachability_status": "NO_FUNCTION_DATA",
                        "reachability_reason": "OSV advisory does not include affected function names",
                        "reachability_path_length": None,
                        "entry_points_found": None,
                        "dep_resolution_rate": None,
                    })

    return pd.DataFrame(rows)


def export_method_hotspots(
    packages: list[dict], method_client: httpx.Client
) -> pd.DataFrame:
    """
    Export 4: method_hotspots.csv
    Top-20 method hotspots per package.
    """
    rows = []
    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        slug = normalize_slug(name, eco)

        logger.info(f"[{i}/{len(packages)}] Hotspots: {slug}")

        hotspots = safe_get(method_client, f"/methods/{slug}/hotspots", params={"limit": 20})
        if not hotspots:
            continue

        for rank, h in enumerate(hotspots, 1):
            method = h.get("method", {})
            metrics = h.get("metrics", {})
            rows.append({
                "ecosystem": eco,
                "package": name,
                "version": pkg["version"],
                "rank": rank,
                "method_name": method.get("name", ""),
                "method_id": method.get("id", ""),
                "file_path": method.get("file_path", ""),
                "class_name": method.get("class_name", ""),
                "qualified_name": method.get("qualified_name", ""),
                "complexity": metrics.get("complexity", 0),
                "loc": metrics.get("loc", 0),
                "fan_in": metrics.get("fan_in", 0),
                "fan_out": metrics.get("fan_out", 0),
                "fan_out_external": metrics.get("fan_out_external", 0),
                "bottleneck_score": metrics.get("bottleneck_score", 0.0),
                "betweenness_centrality": metrics.get("betweenness_centrality"),
                "pagerank": metrics.get("pagerank"),
                "eigenvector_centrality": metrics.get("eigenvector_centrality"),
                "blast_radius": metrics.get("blast_radius"),
                "community_id": metrics.get("community_id"),
                "is_leaf": metrics.get("is_leaf", False),
                "is_orphan": metrics.get("is_orphan", False),
                "structural_risk": h.get("structural_risk", 0.0),
                "composite_risk": h.get("composite_risk", 0.0),
                "temporal_factor": h.get("temporal_factor", 1.0),
                "git_data_available": h.get("git_data_available", False),
            })

    return pd.DataFrame(rows)


def export_temporal_profiles(
    packages: list[dict], dep_client: httpx.Client, method_client: httpx.Client
) -> pd.DataFrame:
    """
    Export 5: temporal_profiles.csv
    Version timeline + git churn per package.
    """
    rows = []
    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        slug = normalize_slug(name, eco)

        logger.info(f"[{i}/{len(packages)}] Temporal: {eco}/{name}")

        # Git profile from method observatory
        git = safe_get(method_client, f"/methods/{slug}/git-profile")

        rows.append({
            "ecosystem": eco,
            "package": name,
            "version": pkg["version"],
            "category": pkg.get("category", ""),
            # Git health metrics
            "git_total_commits": git.get("total_commits") if git else None,
            "git_total_contributors": git.get("total_contributors") if git else None,
            "git_active_contributors_90d": git.get("active_contributors_90d") if git else None,
            "git_bus_factor": git.get("bus_factor") if git else None,
            "git_days_since_last_commit": git.get("days_since_last_commit") if git else None,
            "git_commits_in_window": git.get("commits_in_window") if git else None,
            "git_first_commit": git.get("first_commit_date") if git else None,
            "git_last_commit": git.get("last_commit_date") if git else None,
        })

    return pd.DataFrame(rows)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OSCAR Research Data Export")
    parser.add_argument("--corpus", default="scripts/corpus.json", help="Path to corpus JSON file")
    parser.add_argument("--output-dir", default="research_data", help="Output directory for CSV files")
    parser.add_argument("--dep-url", default=DEFAULT_DEP_URL, help="Dependency Observatory base URL")
    parser.add_argument("--method-url", default=DEFAULT_METHOD_URL, help="Method Observatory base URL")
    parser.add_argument(
        "--only", default=None,
        help="Comma-separated list of exports to run: summary,cross_level,vulns,hotspots,temporal"
    )
    args = parser.parse_args()

    # Load corpus
    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        logger.error(f"Corpus file not found: {corpus_path}")
        sys.exit(1)

    with open(corpus_path) as f:
        corpus = json.load(f)
    packages = corpus["packages"]
    logger.info(f"Loaded {len(packages)} packages from {corpus_path}")

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine which exports to run
    all_exports = {"summary", "cross_level", "vulns", "hotspots", "temporal"}
    exports_to_run = all_exports
    if args.only:
        exports_to_run = set(args.only.split(","))
        invalid = exports_to_run - all_exports
        if invalid:
            logger.error(f"Unknown export names: {invalid}. Valid: {all_exports}")
            sys.exit(1)

    # Create HTTP clients
    dep_client = httpx.Client(base_url=args.dep_url, timeout=TIMEOUT)
    method_client = httpx.Client(base_url=args.method_url, timeout=TIMEOUT)

    # Verify connectivity
    try:
        health = dep_client.get("/health")
        assert health.status_code == 200, f"Dependency Observatory not healthy: {health.status_code}"
        logger.info("✅ Dependency Observatory connected")
    except Exception as e:
        logger.error(f"❌ Cannot reach Dependency Observatory at {args.dep_url}: {e}")
        sys.exit(1)

    try:
        projects = method_client.get("/methods/projects")
        assert projects.status_code == 200, f"Method Observatory not healthy: {projects.status_code}"
        logger.info(f"✅ Method Observatory connected ({len(projects.json())} cached projects)")
    except Exception as e:
        logger.error(f"❌ Cannot reach Method Observatory at {args.method_url}: {e}")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {}

    # ── Run exports ──
    if "summary" in exports_to_run:
        logger.info("\n═══ Export 1/5: Corpus Summary ═══")
        df = export_corpus_summary(packages, dep_client, method_client)
        path = output_dir / f"corpus_summary_{timestamp}.csv"
        df.to_csv(path, index=False)
        results["summary"] = (path, len(df))
        logger.info(f"  → {path} ({len(df)} rows)")

    if "cross_level" in exports_to_run:
        logger.info("\n═══ Export 2/5: Cross-Level Results ═══")
        df = export_cross_level_results(packages, dep_client)
        path = output_dir / f"cross_level_results_{timestamp}.csv"
        df.to_csv(path, index=False)
        results["cross_level"] = (path, len(df))
        logger.info(f"  → {path} ({len(df)} rows)")

    if "vulns" in exports_to_run:
        logger.info("\n═══ Export 3/5: Vulnerability Results ═══")
        df = export_vulnerability_results(packages, dep_client, method_client)
        path = output_dir / f"vulnerability_results_{timestamp}.csv"
        df.to_csv(path, index=False)
        results["vulns"] = (path, len(df))
        logger.info(f"  → {path} ({len(df)} rows)")

    if "hotspots" in exports_to_run:
        logger.info("\n═══ Export 4/5: Method Hotspots ═══")
        df = export_method_hotspots(packages, method_client)
        path = output_dir / f"method_hotspots_{timestamp}.csv"
        df.to_csv(path, index=False)
        results["hotspots"] = (path, len(df))
        logger.info(f"  → {path} ({len(df)} rows)")

    if "temporal" in exports_to_run:
        logger.info("\n═══ Export 5/5: Temporal Profiles ═══")
        df = export_temporal_profiles(packages, dep_client, method_client)
        path = output_dir / f"temporal_profiles_{timestamp}.csv"
        df.to_csv(path, index=False)
        results["temporal"] = (path, len(df))
        logger.info(f"  → {path} ({len(df)} rows)")

    # ── Summary ──
    dep_client.close()
    method_client.close()

    logger.info("\n" + "═" * 60)
    logger.info("EXPORT COMPLETE")
    logger.info("═" * 60)
    for name, (path, count) in results.items():
        logger.info(f"  {name:15s} → {path.name} ({count} rows)")
    logger.info(f"\nAll files saved to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
