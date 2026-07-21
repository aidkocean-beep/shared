---
name: vulnerability-analyzer
description: Analyze Sonatype vulnerability findings against the current project and produce a triage report (violation explanation, impact/reachability analysis, disposition recommendation, and mitigation path when no fix exists). Uses an incremental local cache to avoid re-reading source code or re-analyzing unchanged findings across repeated runs. Use when the user provides a Sonatype vulnerability list (CVE/reference + package + version) and asks for triage, analysis, waiver justification, or a remediation report.
---

# Vulnerability Analysis & Triage Skill (Incremental, Cache-Backed)

## Purpose

Given a list of vulnerabilities from Sonatype (package + version + CVE/reference number), produce
a per-finding triage report that answers, for each item:

1. **What is the violation** — plain-language explanation of the CVE/CWE and why it's flagged.
2. **Is this project actually impacted** — is the vulnerable component reachable/used in a way
   that matters, or just present in the tree unused.
3. **Disposition** — one of:
   - `FIX_REQUIRED` — patch available, apply it (direct bump or forced transitive override).
   - `WAIVER_FALSE_POSITIVE` — vulnerable code path is not reachable/exercised in this project.
   - `WAIVER_NOT_APPLICABLE` — vulnerability requires a precondition this project doesn't meet
     (wrong runtime context, feature not used, server-only issue in a client-only usage, etc).
   - `ACCEPT_RISK_TEMPORARY` — real exposure exists, no fix yet, risk is acceptable short-term
     with compensating controls; requires a re-review date.
   - `MUST_FIX_NO_PATCH` — no fixed version exists AND risk cannot be reasonably accepted;
     requires an alternative mitigation (replace library, isolate feature, disable code path,
     network-level control) rather than a version bump.
4. **If unfixable** — explicitly state whether it's a hard "must fix via other means" or a
   "safe to accept and monitor," with reasoning, not just "no fix available."

This skill MUST use the local cache described below. It must NOT re-read the full codebase on
every run — only the minimal set of files needed to answer reachability for **new or changed**
findings since the last run.

---

## 1. Inputs

### 1.1 Vulnerability list (required, provided by the user each run)

Accepts CSV, JSON, or pasted table. Minimum required columns/fields:

```
package_ecosystem   e.g. npm, maven, pypi
package_name        e.g. ws, org.springframework:spring-core
current_version     e.g. 7.5.10
reference           CVE/GHSA/Sonatype ID, e.g. CVE-2026-48779
```

Optional fields if available from Sonatype: `severity`, `cvss`, `dependency_path` (direct vs
transitive chain), `sonatype_threat_category`.

### 1.2 Local cache file (auto-managed by this skill)

Path: `.copilot/vuln-cache.json` at the project root. Create it if missing. This is the
mechanism that makes repeated runs cheap.

```json
{
  "schemaVersion": 1,
  "lastUpdated": "2026-07-21T00:00:00Z",
  "projectFingerprint": {
    "manifestHashes": {
      "package.json": "sha256:...",
      "package-lock.json": "sha256:...",
      "pom.xml": "sha256:..."
    }
  },
  "dependencyGraph": {
    "npm": {
      "ws": { "version": "7.5.10", "isDirect": false, "parents": ["some-lib"] }
    },
    "maven": {
      "org.springframework:spring-core": { "version": "5.3.20", "isDirect": true, "parents": [] }
    }
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
      "reachabilityEvidence": ["src/gateway/wsServer.ts:42 — new WebSocketServer(...)"],
      "disposition": "FIX_REQUIRED",
      "fixedVersion": "7.5.11",
      "isBreakingChange": false,
      "effort": "LOW",
      "justification": "Direct WebSocket server usage found; patch is a clean patch-version bump.",
      "reviewBy": null,
      "analyzedAt": "2026-07-21T00:00:00Z",
      "codeFilesChecked": ["src/gateway/wsServer.ts"],
      "codeFilesHash": "sha256:..."
    }
  }
}
```

Key design points:
- The cache key is `reference|ecosystem|package|version` — if the *version* changes (e.g. after
  a Renovate PR merges), the old entry is stale and must be re-analyzed; don't silently reuse it.
- `codeFilesChecked` + `codeFilesHash` let the skill detect if the specific files it relied on for
  a reachability verdict have since changed, without hashing the whole repo.
- `reviewBy` is mandatory whenever `disposition` is `ACCEPT_RISK_TEMPORARY` or any `WAIVER_*`.

---

## 2. Workflow (run this every time, in order)

### Step 1 — Load or initialize cache
Read `.copilot/vuln-cache.json`. If it doesn't exist, create it empty (do not treat that as an
error, just start a fresh analysis for everything in the input list).

### Step 2 — Diff the input list against the cache
For every row in the new vulnerability list, compute the cache key
(`reference|ecosystem|package|current_version`) and classify it as:

- **UNCHANGED** — key exists in cache with `status: ANALYZED`, and the version matches, and
  none of `codeFilesChecked` have changed (check mtime/hash cheaply, don't re-read content unless
  changed) → reuse the cached analysis verbatim. **Do not re-read source or re-reason about it.**
- **NEW** — key not in cache at all → full analysis (Step 3).
- **VERSION_CHANGED** — same reference+package, different version than what's cached → treat as
  a fresh analysis (patch may already be applied, or the situation may have changed).
- **STALE_CODE** — cached but a checked file's hash changed since last analysis → re-verify
  reachability only (skip re-deriving the CVE explanation, which doesn't change).

Any cache entries whose key is **no longer present** in the current input list should be left in
the cache (don't delete — they're historical record) but excluded from the current report unless
the user asks for a full history view. If the user explicitly says a package/reference was
removed from scope, mark it `status: "OUT_OF_SCOPE"` rather than deleting the entry.

### Step 3 — Analyze NEW / VERSION_CHANGED / STALE_CODE items only

For each:

1. **Explain the violation** — describe the CWE/CVE mechanism in plain language (what an
   attacker does, what class of weakness it is). Don't just restate the Sonatype description;
   explain *why* it matters.
2. **Determine direct vs transitive** and the dependency chain (use the cached
   `dependencyGraph` if already built this run; only regenerate the dependency tree once per run
   even if multiple findings need it — e.g. run `npm ls`, `mvn dependency:tree`,
   `pip show`/`pipdeptree` a single time and reuse the output for every finding in that
   ecosystem).
3. **Reachability check** (the expensive step — keep it targeted):
   - Identify the specific vulnerable function/API/code path from the CVE advisory.
   - Search the codebase **only** for usage of that specific package/API (grep/ripgrep for
     import statements and the relevant call sites) — do not open unrelated files, and do not
     read entire directories "just in case."
   - Record the exact file(s)/line(s) found as `reachabilityEvidence`, or explicitly record "no
     usage found" if the package is present only as an unused transitive dependency.
4. **Check fix availability**:
   - Is there a fixed version? If yes → `FIX_REQUIRED` (or if already unreachable, still note the
     fix exists but disposition follows reachability, see below).
   - If no fixed version exists, determine:
     - Is the vulnerable path reachable/used? If yes → `MUST_FIX_NO_PATCH`: recommend a concrete
       alternative (replace the library, vendor a patched fork, wrap/sanitize the call site,
       disable the affected feature, add a network/WAF control) — never just say "no fix, risk
       accepted" when the code path is genuinely exercised.
     - If no → `ACCEPT_RISK_TEMPORARY` or `WAIVER_NOT_APPLICABLE`, with a mandatory `reviewBy`
       date (default: 90 days out unless the user specifies a cadence).
5. **Assign disposition** using this priority order:
   - Not reachable/used at all → `WAIVER_FALSE_POSITIVE`
   - Reachable, but precondition for exploit doesn't hold in this deployment context (e.g.
     requires a config flag you don't enable) → `WAIVER_NOT_APPLICABLE`
   - Reachable, fix exists → `FIX_REQUIRED`
   - Reachable, no fix, real exposure, no compensating control feasible right now →
     `ACCEPT_RISK_TEMPORARY` (must include compensating controls + review date)
   - Reachable, no fix, exposure is significant/exploitable and no acceptable temporary control →
     `MUST_FIX_NO_PATCH` with alternative mitigation
6. **Estimate effort**: 🟢 Low (version bump only) / 🟡 Medium (override + retest) / 🔴 High
   (requires code change, library replacement, or architecture change).
7. Write the result into `findings[key]` in the cache, including `codeFilesChecked` and their
   current hash, so future runs can detect drift.

### Step 4 — Assemble the report
Combine cached (unchanged) results with newly analyzed results into one report covering the
**current input list only**. Save the updated cache file.

---

## 3. Report format

Produce a markdown table plus a short narrative per non-trivial item. Table columns:

| Reference | Package | Version | Direct/Transitive | Reachable? | Disposition | Fixed Version | Effort | Review By |
|---|---|---|---|---|---|---|---|---|

Below the table, for every item that is `MUST_FIX_NO_PATCH`, `ACCEPT_RISK_TEMPORARY`, or any
`WAIVER_*`, include a short paragraph: violation explanation, reachability evidence (file:line or
"not found"), and justification for the disposition. Items that are straightforward
`FIX_REQUIRED` with a clean patch-version bump can stay as a one-line table row without a
paragraph — don't pad the report with narrative for the easy cases.

End the report with a summary count by disposition, and a separate list of items whose
`reviewBy` date has already passed (these need immediate re-triage, not silent carry-forward).

---

## 4. Token-saving rules (non-negotiable)

- Never re-read the entire source tree. Use targeted search (grep/ripgrep) scoped to the
  package/API in question.
- Build each ecosystem's dependency tree **once per run**, not once per finding.
- For `UNCHANGED` items, copy the cached analysis into the report without re-invoking any
  reasoning or file reads.
- Only re-verify reachability (not the full CVE explanation) for `STALE_CODE` items — the CVE
  mechanism doesn't change; only whether your code still touches it might.
- When the user says "add package X / reference Y" or "remove package X," only process the
  delta — do not re-run Step 3 for anything already `ANALYZED` and unaffected by the change.

## 5. Handling repeated runs with a changing list

- **Adding items**: only new keys go through Step 3; everything else is reused from cache.
- **Removing items**: mark as `OUT_OF_SCOPE` in cache, exclude from the current report, keep the
  historical entry.
- **Re-running after a Renovate/patch merge**: the version in the new Sonatype export will differ
  from what's cached → treated as `VERSION_CHANGED` → re-analyzed (this is intentional, since the
  fix may have already landed and the finding may simply disappear from Sonatype's next scan).
- **Forcing a full re-analysis** of an item despite an unchanged cache: user can say
  "force-refresh CVE-XXXX" — only then re-derive everything for that one key.
