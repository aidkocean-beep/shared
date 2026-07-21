---
name: vulnerability-analyzer
description: Analyze Sonatype vulnerability findings against the current project's actual source code (never lockfile presence alone) and produce a triage report — violation explanation, prod-reachability analysis with file:line evidence, disposition (fix/waiver/accept-risk/must-fix-alternative), and a concrete code diff for the fix. Uses an incremental local cache to avoid re-reading source or re-analyzing unchanged findings across repeated runs. Use when the user provides a Sonatype vulnerability list (CVE/reference + package + version) and asks for triage, waiver justification, remediation code changes, or a report.
---

# Vulnerability Analysis & Triage Skill (Incremental, Source-Verified, Remediation-Generating)

## Purpose

Given a list of vulnerabilities from Sonatype (package + version + CVE/reference number), produce
a per-finding triage report that:

1. Explains the violation in plain language.
2. Determines whether the vulnerable component is actually used in source — and specifically
   whether that usage is in a **production** code path, not just present in a lockfile or used
   only in tests/build tooling.
3. Assigns a disposition: `FIX_REQUIRED`, `WAIVER_FALSE_POSITIVE`, `WAIVER_NOT_APPLICABLE`,
   `ACCEPT_RISK_TEMPORARY`, or `MUST_FIX_NO_PATCH` (see definitions below).
4. Produces an actual **code diff or concrete change** for the fix — not just a target version
   number — using the real file/syntax found in this repo.
5. Does all of the above incrementally: unchanged findings from a prior run are reused from
   cache with zero re-analysis and zero source re-reads.

> **Anti-pattern to avoid**: concluding a finding is a "match" or drawing any disposition purely
> because the package/version appears in `package-lock.json`, `pom.xml`'s resolved tree,
> `poetry.lock`, `requirements.txt`, etc. That only confirms Sonatype's scan is right about what's
> *installed* — it adds zero triage value alone. Every disposition must be backed by an actual
> source-code search result (`file:line`, or an explicit "no usage found anywhere in source"),
> and every "yes it's used" verdict must state whether that usage is in a production code path.

## Bundled reference files (load on demand, not upfront)

- `references/language-patterns.md` — per-ecosystem search commands, and how to tell prod vs
  test/build-only source for each. Load when doing Step 3 below.
- `references/remediation-patterns.md` — concrete diff templates for direct bumps, transitive
  overrides, and no-fix mitigations (wrapper/sanitize, feature-disable, replace library, vendor
  patch, network control). Load when doing Step 5 below.
- `references/report-format.md` — the finding-card template and summary rules. Load when
  assembling the final report.

Keep these out of context until the relevant step — this file stays the workflow driver; the
reference files carry the bulk detail so re-runs don't reload everything.

---

## Disposition definitions

- `FIX_REQUIRED` — patch available, apply it (direct bump or forced transitive override).
- `WAIVER_FALSE_POSITIVE` — no usage of the vulnerable API found anywhere in source at all.
- `WAIVER_NOT_APPLICABLE` — used, but only in test/build-only code excluded from the shipped
  artifact, OR the exploit precondition doesn't hold in this deployment.
- `ACCEPT_RISK_TEMPORARY` — prod-reachable, no fix yet, risk is acceptable short-term with
  compensating controls; mandatory `reviewBy` date.
- `MUST_FIX_NO_PATCH` — prod-reachable, no fixed version exists, and risk cannot be reasonably
  accepted; requires an alternative mitigation (see remediation-patterns.md §3), not a version
  bump.

---

## 1. Inputs

### 1.1 Vulnerability list (provided by the user each run)
CSV, JSON, or pasted table with at minimum: `package_ecosystem`, `package_name`,
`current_version`, `reference` (CVE/GHSA/Sonatype ID). Optional: `severity`, `cvss`,
`dependency_path`.

### 1.2 Local cache — `.copilot/vuln-cache.json` (auto-managed, create if missing)

```json
{
  "schemaVersion": 2,
  "lastUpdated": "2026-07-21T00:00:00Z",
  "dependencyGraph": {
    "npm": { "ws": { "version": "7.5.10", "isDirect": false, "parents": ["some-lib"] } }
  },
  "findings": {
    "CVE-2026-48779|npm|ws|7.5.10": {
      "status": "ANALYZED",
      "reference": "CVE-2026-48779",
      "package": "ws",
      "ecosystem": "npm",
      "analyzedVersion": "7.5.10",
      "isDirect": false,
      "reachable": true,
      "prodReachable": true,
      "reachabilityEvidence": [
        "src/gateway/wsServer.ts:42 — new WebSocketServer(...) — prod source, ships in Docker image"
      ],
      "disposition": "FIX_REQUIRED",
      "fixedVersion": "7.5.11",
      "suggestedDiff": "package.json: \"ws\": \"7.5.10\" -> \"7.5.11\"",
      "isBreakingChange": false,
      "effort": "LOW",
      "justification": "Direct WebSocket server usage confirmed at wsServer.ts:42; clean patch bump.",
      "reviewBy": null,
      "verifiedByJudgePass": true,
      "analyzedAt": "2026-07-21T00:00:00Z",
      "codeFilesChecked": ["src/gateway/wsServer.ts"],
      "codeFilesHash": "sha256:..."
    }
  }
}
```

Cache key: `reference|ecosystem|package|version`. If the version changes, the entry is stale and
must be re-analyzed. `codeFilesChecked`/`codeFilesHash` let re-runs detect drift in just the files
that mattered for a given finding, without hashing the whole repo.

---

## 2. Workflow

### Step 1 — Load or initialize cache
Read `.copilot/vuln-cache.json`; create empty if missing.

### Step 2 — Diff input list against cache
Classify each row as **UNCHANGED** (reuse verbatim, no re-analysis, no source re-reads),
**NEW**, **VERSION_CHANGED**, or **STALE_CODE** (checked file hash changed — re-verify
reachability only, the CVE explanation doesn't need re-deriving). Entries removed from the input
list are marked `OUT_OF_SCOPE` in cache, not deleted, and excluded from the current report.

### Step 3 — Reachability analysis (NEW / VERSION_CHANGED / STALE_CODE only)
Load `references/language-patterns.md` for the relevant ecosystem(s). For each finding:
1. Identify the vulnerable surface from the advisory (specific function/class/config option).
2. Run the targeted search commands from the reference file — scoped to that package/API only.
3. Classify every match as production source or test/build-only, per the reference file's rules
   for that ecosystem.
4. Record two distinct booleans: `reachable` (used anywhere, including tests) and
   `prodReachable` (used in code that ships). Cite `file:line` for every "yes."
5. Build each ecosystem's dependency tree **once per run** (not once per finding) and reuse it.

### Step 4 — Verification pass ("judge" step, reduces false positives/negatives)
Before finalizing a disposition, re-check your own conclusion against the evidence:
- Does the cited `file:line` actually construct/call the vulnerable surface, or just reference an
  unrelated export from the same package? If the latter, this is not evidence of reachability —
  say so and keep searching or mark not-found.
- If claiming "test-only, excluded from prod," did you actually check the build/packaging config
  (Dockerfile final stage, `pom.xml` scope + shade/assembly plugin, `poetry install --only main`
  flag in CI), or did you assume from directory naming alone? If you didn't check, say so
  explicitly rather than asserting it as fact.
- If claiming "no fixed version exists," did you check the actual advisory/registry for a version
  newer than what you assumed, not just the version in the Sonatype export?
Set `verifiedByJudgePass: true` only after this check; if you can't verify a claim, state the
uncertainty in the report instead of forcing a confident answer.

### Step 5 — Generate concrete remediation
Load `references/remediation-patterns.md`. For every `FIX_REQUIRED` or `MUST_FIX_NO_PATCH`
finding, produce an actual diff/snippet using the real file path, current version, and syntax
found in Step 3 — not a generic example. Include what to re-test and the breaking-change risk.
Store this in `suggestedDiff` in the cache so re-runs don't have to regenerate it unless the
finding is re-analyzed.

### Step 6 — Assemble report and save cache
Load `references/report-format.md`. Combine cached + newly analyzed results into one report
covering the current input list. Save the updated cache.

---

## 3. Token-saving rules (non-negotiable)

- Never re-read the entire source tree; use targeted search scoped to the specific package/API.
- Build each ecosystem's dependency tree once per run, not once per finding.
- `UNCHANGED` items are copied from cache with zero re-analysis, zero file reads, zero
  regeneration of the diff.
- `STALE_CODE` items only get reachability + remediation re-verified, not the CVE explanation.
- Adding/removing items from the list only triggers processing of the delta.
- Load the three reference files only when their corresponding step is reached, not all at once
  at the start of a run.

## 4. Handling repeated runs with a changing list

- **Adding items**: only new keys go through Steps 3–5.
- **Removing items**: mark `OUT_OF_SCOPE`, exclude from report, keep historical record.
- **Re-running after a Renovate/patch merge**: version differs from cache → `VERSION_CHANGED` →
  re-analyzed (the finding may simply disappear from Sonatype's next scan if already fixed).
- **Force a full re-analysis** of one item regardless of cache state: user says
  "force-refresh CVE-XXXX."
