# Automated CVE Patch Mining — Technical Deep Dive

> **Context:** This document explains the automated patch mining technique used in the OSCAR ICSE 2027 paper to recover function-level CVE data from fix commits. It is written to be understood independently of the paper.

---

## The Problem

Software Composition Analysis (SCA) tools alert developers when their dependencies contain known vulnerabilities (CVEs). A major source of false positives is **package-level alerting**: the tool warns about a CVE in dependency X, but the vulnerable function is never actually called by the application.

**Reachability analysis** can determine whether a vulnerable function is reachable from the application's call paths. However, this requires knowing *which specific function* is affected — and this data is rarely available:

| Advisory Database | Field | Population Rate |
|------------------|-------|----------------|
| OSV (Google) | `affected.ranges.events.affected_functions` | **~0%** (schema exists, rarely populated) |
| NVD (NIST) | CWE + CPE only | No function-level data |
| GitHub Advisory | `vulnerabilities[].vulnerable_functions` | **~0%** |
| Eclipse Steady | Internal DB | Populated via this exact technique |

## The Insight

Every CVE is fixed by a commit. The commit diff reveals exactly which functions were modified. Therefore:

> **The set of functions modified in a CVE fix commit is a reliable approximation of the affected functions.**

This is the same principle used by Eclipse Steady (SAP's vulnerability assessment tool), but our implementation operates purely on public data via the GitHub Advisory API, without requiring access to private build systems.

## The Pipeline

```
GHSA-xxxx-yyyy-zzzz
        │
        ▼
┌───────────────────────┐
│  GitHub Advisory API   │  GET /advisories/{GHSA-ID}
│  Response includes:    │
│   • references[] URLs  │──── Extract commit URLs matching:
│   • severity           │     github.com/{owner}/{repo}/commit/{sha}
│   • affected packages  │     github.com/{owner}/{repo}/pull/{N}
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  GitHub .diff Endpoint │  GET /{owner}/{repo}/commit/{sha}.diff
│                        │
│  Returns unified diff  │──── Raw text, no API auth required
│  with hunk headers     │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────────────────────────┐
│            Diff Parser                     │
│                                            │
│  1. Track current file from diff headers   │
│  2. Skip test files (test/, spec/, etc.)   │
│  3. Extract from @@ hunk headers           │
│  4. Extract from +/- modified lines        │
│  5. Apply language-aware regex patterns     │
│  6. Filter keywords and dedup              │
└───────────┬───────────────────────────────┘
            │
            ▼
    { parseObject, sanitizeHeader, ... }
         (set of affected function names)
```

## Diff Parsing — The Core Algorithm

### Source 1: Git Hunk Headers

Git includes contextual information in the `@@` line of unified diffs. For code files, this is typically the name of the enclosing function:

```diff
diff --git a/lib/parse.js b/lib/parse.js
--- a/lib/parse.js
+++ b/lib/parse.js
@@ -42,7 +42,9 @@ var parseObject = function (chain, val, options, valuesParsed) {
     if (keys.length === 0) {
-        return;
+        if (valuesParsed >= options.arrayLimit) {
+            throw new RangeError('Array limit exceeded');
+        }
```

The text after the second `@@` — `var parseObject = function (chain, ...` — tells us the modification occurred inside `parseObject`. Our regex extracts `parseObject` from this context.

**Why this matters:** Even if the function definition wasn't modified, the hunk header reveals which function *contains* the fix.

### Source 2: Modified Function Definitions

Lines prefixed with `+` (added) or `-` (removed) that match function definition patterns:

```diff
+function sanitizeHeaderValue(value) {
-function oldUnsafeMethod(input) {
+exports.isValidHeader = function(name) {
```

### Language-Specific Patterns

**Python patterns** (3 regex rules):
```
^\s*def\s+(\w+)\s*\(         →  def function_name(
^\s*async\s+def\s+(\w+)\s*\( →  async def function_name(
^\s*class\s+(\w+)\s*[\(:]     →  class ClassName(
```

**JavaScript patterns** (7 regex rules):
```
^\s*function\s+(\w+)\s*\(                    →  function name(
^\s*(?:const|let|var)\s+(\w+)\s*=\s*function  →  const name = function(
^\s*(?:const|let|var)\s+(\w+)\s*=.*=>         →  const name = () =>
^\s*(\w+)\s*\([^)]*\)\s*\{                    →  name() {    (method)
^\s*exports\.(\w+)\s*=                        →  exports.name =
^\s*module\.exports\.(\w+)\s*=                →  module.exports.name =
^\s*(?:async\s+)?(\w+)\s*=.*=>                →  name = async () =>
```

### Filtering Rules

1. **Test files excluded:** Files matching `test/`, `tests/`, `__tests__/`, `*.test.js`, `*_test.py`, `spec/`
2. **Keywords excluded:** `if`, `for`, `while`, `return`, `switch`, `try`, `catch`, `throw`, `new`, `delete`, `typeof`, `constructor`, `describe`, `it`, `test`, `expect`

## Results from Our Corpus

| Metric | Value |
|--------|-------|
| GHSA advisories processed | 45 |
| With fix commits found | 41 (91%) |
| With functions mined | 31 (69%) |
| Total unique functions extracted | 133 |
| Avg functions per advisory | 4.3 |

### Per-Package Breakdown

| Package | CVEs | Functions Mined | Example Functions |
|---------|------|----------------|-------------------|
| urllib3 | 13 | 36 | `read()`, `stream()`, `connect()`, `ssl_wrap_socket()` |
| axios | 5 | 46 | `extend()`, `toFlatObject()`, `sanitizeHeaderValue()` |
| starlette | 2 | 15 | `_parse_ranges()`, `_handle_single_range()` |
| follow-redirects | 1 | 5 | `isURL()`, `isSubdomain()`, `RedirectableRequest()` |
| pydantic | 2 | 5 | `validate_email()`, `get_numeric()` |
| qs | 2 | 1 | `parseObject()` |

### Why Some Advisories Yield Zero Functions

| Reason | Count | Example |
|--------|-------|---------|
| Fix commit not in advisory references | 4 | GHSA-27v5-c462-wpq7 (path-to-regexp) |
| Fix is in configuration/data files only | 3 | GHSA-xqr8-7jwr-rhp7 (certifi — CA cert removal) |
| Minified code with obfuscated names | 1 | GHSA-xxjr-mmjv-4gpg (lodash → `Vo`, `Xc`, `Ye`) |
| Fix is only in regex/constant changes | 6 | GHSA-w7fw-mjwx-w883 (qs — regex hardening) |

## Known Limitations

1. **Top-20 hotspot matching:** The current implementation matches mined functions only against the top-20 risk-ranked methods per package. Functions that exist in the full call graph but aren't hotspots appear as "unmatched." Fix: query the full graph endpoint instead.

2. **Minified JavaScript:** Packages distributed as minified bundles (e.g., lodash) have obfuscated function names (`Vo`, `Xc`) that don't match the source-level names in our AST-based call graph. Fix: add source map resolution or analyze pre-minification source.

3. **Multi-file fixes:** Large CVE fixes that span many files may introduce noise (utility functions modified alongside the vulnerable function). Our test-file filtering reduces this, but quality could improve with more aggressive denoising.

4. **Class-level granularity:** For Python fixes inside class methods, we sometimes capture the class name instead of the specific method. Our patterns handle `def method_name(self, ...)` but may miss deeply nested inner functions.

5. **Hunk header ambiguity:** In files with deeply nested functions, the hunk header may show an outer function when the fix is in an inner function. This is a Git limitation, not solvable at the diff parsing level.

## Reuse Potential

### As an OSV Enrichment Service

The pipeline could be wrapped as a service that enriches OSV advisories with function-level data:

```
Input:  GHSA-6rw7-vpxm-498p
Output: { "affected_functions": ["parseObject"], "confidence": 0.9, "source": "fix_commit_diff" }
```

This would benefit any SCA tool that performs reachability analysis.

### As a Training Data Source for ML Models

The mined (CVE → function) mappings could serve as labeled training data for vulnerability prediction models. The 133 functions across 31 advisories is a starting point; running the pipeline on the full GHSA database (~3,000 npm + PyPI advisories) would produce thousands of labeled examples.

### Integration with Other Call Graph Tools

The function names produced by the pipeline are language-level identifiers (e.g., `parseObject`, `read_chunked`). They can be matched against any call graph representation — not just OSCAR's. This makes the technique compatible with PyCG, Wala, Soot, or any tool that outputs function-name-level call graphs.
