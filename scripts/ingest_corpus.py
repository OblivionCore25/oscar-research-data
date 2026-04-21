#!/usr/bin/env python3
"""
OSCAR Research Corpus Ingestion Script

Batch-ingests all packages from corpus.json into both OSCAR observatories:
  1. Dependency Observatory (port 8000) — transitive graph + enrichment
  2. Method Observatory (port 8001)    — AST call graph + metrics

Usage:
    python ingest_corpus.py [--corpus scripts/corpus.json] [--skip-dep] [--skip-method]

Prerequisites:
    pip install httpx
    Both OSCAR services running on ports 8000 and 8001
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oscar-ingest")

DEFAULT_DEP_URL = "http://127.0.0.1:8000"
DEFAULT_METHOD_URL = "http://127.0.0.1:8001"

# Ingestion can take a while (npm tarball download + AST parsing)
INGEST_TIMEOUT = httpx.Timeout(120.0, connect=10.0)
# Graph resolution can also be slow for deep trees
GRAPH_TIMEOUT = httpx.Timeout(180.0, connect=10.0)


def normalize_slug(package_name: str, ecosystem: str) -> str:
    """Match the method observatory slug normalization."""
    slug = package_name.replace("@", "").replace("/", "__")
    if ecosystem.lower() == "pypi":
        slug = slug.lower()
    return slug


def is_already_ingested_method(client: httpx.Client, slug: str) -> bool:
    """Check if a project is already in the method observatory."""
    try:
        r = client.get(f"/methods/{slug}", timeout=10.0)
        return r.status_code == 200
    except Exception:
        return False


def is_already_ingested_dep(client: httpx.Client, eco: str, name: str, version: str) -> bool:
    """Check if a package is already in the dependency observatory (without triggering ingestion)."""
    try:
        # Use the list endpoint which queries storage only — doesn't trigger auto-ingest
        r = client.get(f"/packages", params={"ecosystem": eco, "q": name, "limit": 50}, timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            for pkg in data.get("packages", []):
                if pkg.get("name") == name and pkg.get("version") == version:
                    return True
        return False
    except Exception:
        return False


def ingest_dependency_observatory(
    client: httpx.Client, eco: str, name: str, version: str
) -> dict:
    """
    Trigger dependency ingestion via GET /packages/{eco}/{name}/{ver}.

    The Dependency Observatory auto-ingests when you query package details -
    it fetches from the registry, resolves the transitive graph, and computes
    all metrics. There is no separate POST /ingest endpoint.
    """
    result = {"ecosystem": eco, "package": name, "version": version}

    # Step 1: Fetch package details (auto-ingests + resolves transitive graph)
    try:
        r = client.get(
            f"/packages/{eco}/{name}/{version}",
            timeout=GRAPH_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            metrics = data.get("metrics", {})
            result["ingest_status"] = "ok"
            result["blast_radius"] = metrics.get("blastRadius", 0)
            result["transitive_depth"] = metrics.get("transitiveDepth", 0)
        else:
            result["ingest_status"] = f"error_{r.status_code}"
            result["error"] = r.text[:200]
            return result
    except httpx.TimeoutException:
        result["ingest_status"] = "timeout"
        return result
    except Exception as e:
        result["ingest_status"] = "error"
        result["error"] = str(e)[:200]
        return result

    # Step 2: Trigger enrichment (global fan-in, scorecard, etc.)
    try:
        r = client.get(
            f"/analytics/enrich/{eco}/{name}/{version}",
            timeout=60.0,
        )
        if r.status_code == 200:
            data = r.json()
            result["enrichment_status"] = "ok"
            result["global_fan_in"] = data.get("globalFanIn")
        else:
            result["enrichment_status"] = f"error_{r.status_code}"
    except Exception as e:
        result["enrichment_status"] = f"error: {str(e)[:100]}"

    return result


def ingest_method_observatory(
    client: httpx.Client, eco: str, name: str, version: str
) -> dict:
    """
    Trigger method-level analysis via auto-ingest endpoint.
    Returns a result dict with status info.
    """
    result = {"ecosystem": eco, "package": name, "version": version}

    try:
        params = {}
        if eco.lower() == "pypi":
            params["version"] = version

        r = client.post(
            f"/methods/ingest/{eco}/{name}",
            params=params,
            timeout=INGEST_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            result["method_status"] = "ok"
            result["slug"] = data.get("project_slug", "")
            result["is_meta_package"] = data.get("is_meta_package", False)
        else:
            result["method_status"] = f"error_{r.status_code}"
            result["error"] = r.text[:200]
    except httpx.TimeoutException:
        result["method_status"] = "timeout"
    except Exception as e:
        result["method_status"] = "error"
        result["error"] = str(e)[:200]

    # Step 2: Trigger git profile analysis
    slug = normalize_slug(name, eco)
    try:
        r = client.post(
            f"/methods/git-profile/{eco}/{name}",
            params={"version": version} if eco.lower() == "pypi" else {},
            timeout=INGEST_TIMEOUT,
        )
        if r.status_code == 200:
            result["git_status"] = "ok"
        else:
            result["git_status"] = f"error_{r.status_code}"
    except httpx.TimeoutException:
        result["git_status"] = "timeout"
    except Exception as e:
        result["git_status"] = f"error: {str(e)[:100]}"

    return result


def main():
    parser = argparse.ArgumentParser(description="OSCAR Research Corpus Ingestion")
    parser.add_argument("--corpus", default="scripts/corpus.json", help="Path to corpus JSON")
    parser.add_argument("--dep-url", default=DEFAULT_DEP_URL, help="Dependency Observatory URL")
    parser.add_argument("--method-url", default=DEFAULT_METHOD_URL, help="Method Observatory URL")
    parser.add_argument("--skip-dep", action="store_true", help="Skip dependency observatory ingestion")
    parser.add_argument("--skip-method", action="store_true", help="Skip method observatory ingestion")
    parser.add_argument("--skip-existing", action="store_true", help="Skip packages already ingested")
    parser.add_argument("--start-from", type=int, default=0, help="Start from Nth package (0-indexed, for resuming)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be ingested without doing it")
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

    if args.start_from > 0:
        packages = packages[args.start_from:]
        logger.info(f"Starting from index {args.start_from}, {len(packages)} packages remaining")

    if args.dry_run:
        for i, pkg in enumerate(packages):
            eco, name, ver = pkg["ecosystem"], pkg["name"], pkg["version"]
            logger.info(f"  [{i}] {eco}/{name}@{ver} ({pkg.get('category', '')})")
        logger.info(f"\nDry run complete. {len(packages)} packages would be ingested.")
        return

    # Create clients
    dep_client = httpx.Client(base_url=args.dep_url, timeout=INGEST_TIMEOUT)
    method_client = httpx.Client(base_url=args.method_url, timeout=INGEST_TIMEOUT)

    # Verify connectivity
    if not args.skip_dep:
        try:
            h = dep_client.get("/health")
            assert h.status_code == 200
            logger.info("✅ Dependency Observatory connected")
        except Exception as e:
            logger.error(f"❌ Cannot reach Dependency Observatory: {e}")
            sys.exit(1)

    if not args.skip_method:
        try:
            p = method_client.get("/methods/projects")
            assert p.status_code == 200
            cached = len(p.json())
            logger.info(f"✅ Method Observatory connected ({cached} cached projects)")
        except Exception as e:
            logger.error(f"❌ Cannot reach Method Observatory: {e}")
            sys.exit(1)

    # ── Ingest loop ──
    results = []
    success_dep = 0
    success_method = 0
    skipped = 0
    failed = 0
    start_time = time.time()

    for i, pkg in enumerate(packages, 1):
        eco = pkg["ecosystem"]
        name = pkg["name"]
        version = pkg["version"]
        category = pkg.get("category", "")
        slug = normalize_slug(name, eco)

        logger.info(f"\n{'═' * 60}")
        logger.info(f"[{i}/{len(packages)}] {eco}/{name}@{version} ({category})")
        logger.info(f"{'═' * 60}")

        row = {"ecosystem": eco, "package": name, "version": version, "category": category}

        # ── Dependency Observatory ──
        if not args.skip_dep:
            if args.skip_existing and is_already_ingested_dep(dep_client, eco, name, version):
                logger.info("  ⏭️  Dep Observatory: already ingested, skipping")
                row["dep_status"] = "skipped"
            else:
                t0 = time.time()
                dep_result = ingest_dependency_observatory(dep_client, eco, name, version)
                elapsed = time.time() - t0
                row.update(dep_result)
                row["dep_elapsed_s"] = round(elapsed, 1)

                status = dep_result.get("ingest_status", "unknown")
                if status in ("ok", "already_exists"):
                    success_dep += 1
                    logger.info(f"  ✅ Dep Observatory: {status} ({elapsed:.1f}s)")
                else:
                    failed += 1
                    logger.warning(f"  ❌ Dep Observatory: {status}")

        # ── Method Observatory ──
        if not args.skip_method:
            if args.skip_existing and is_already_ingested_method(method_client, slug):
                logger.info("  ⏭️  Method Observatory: already ingested, skipping")
                row["method_status"] = "skipped"
            else:
                t0 = time.time()
                method_result = ingest_method_observatory(method_client, eco, name, version)
                elapsed = time.time() - t0
                row.update(method_result)
                row["method_elapsed_s"] = round(elapsed, 1)

                status = method_result.get("method_status", "unknown")
                if status == "ok":
                    success_method += 1
                    logger.info(f"  ✅ Method Observatory: {status} ({elapsed:.1f}s)")
                else:
                    failed += 1
                    logger.warning(f"  ❌ Method Observatory: {status}")

        results.append(row)

    elapsed_total = time.time() - start_time

    # ── Save ingestion log ──
    log_path = Path("research_data") / "ingestion_log.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # ── Summary ──
    dep_client.close()
    method_client.close()

    logger.info(f"\n{'═' * 60}")
    logger.info("INGESTION COMPLETE")
    logger.info(f"{'═' * 60}")
    logger.info(f"  Total packages:    {len(packages)}")
    logger.info(f"  Dep Observatory:   {success_dep} OK")
    logger.info(f"  Method Observatory:{success_method} OK")
    logger.info(f"  Failed:            {failed}")
    logger.info(f"  Total time:        {elapsed_total:.0f}s ({elapsed_total/60:.1f} min)")
    logger.info(f"  Ingestion log:     {log_path}")


if __name__ == "__main__":
    main()
