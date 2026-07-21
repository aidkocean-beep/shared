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
   that matters, or just present in the tree unused. **This MUST be answered by reading actual
   source code usage, never by the presence of an entry in a lockfile/manifest alone.** A package
   appearing in `package-lock.json`, `pom.xml`'s resolved tree, `poetry.lock`, etc. only proves the
   package is *installed* — it says nothing about whether the vulnerable API is ever called, and
   whether that call site ships to production. Skip this step and the whole report is just a
   restatement of the Sonatype scan with no added value.
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

> **Anti-pattern to avoid**: concluding a finding is a "match" or drawing any disposition purely
> because the package/version appears in `package-lock.json`, `pom.xml`, `poetry.lock`,
> `requirements.txt`, or a resolved dependency tree. That only confirms Sonatype's scan is
> correct about what's *installed* — it adds zero triage value on its own. Every disposition in
> this skill's output must be backed by an actual source-code search result (a real `file:line`
> or an explicit "no import/usage found anywhere in source"), and every "yes it's used" verdict
> must also state whether that usage is in a production code path or only in tests/build tooling.

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
      "prodReachable": true,
      "reachabilityEvidence": [
        "src/gateway/wsServer.ts:42 — new WebSocketServer(...) — production source path, ships in the built Docker image"
      ],
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
3. **Reachability check — MANDATORY source-code verification, never lockfile-only** (this is the
   step that actually determines the disposition; treat it as required evidence-gathering, not an
   optional deep-dive):

   a. **Never stop at "it's in the lockfile / resolved dependency tree."** That only proves the
      package is installed. It is not evidence of usage and must never be cited as
      `reachabilityEvidence` by itself.

   b. **Identify the vulnerable surface from the advisory** — the specific function, class,
      constructor, or config option the CVE describes (e.g. "constructing a `WebSocketServer`
      with fragmented frames," "calling `merge()`/`extend()` with attacker-controlled keys," "the
      `eval`-based template rendering path").

   c. **Search actual source for that surface**, scoped to the specific package — never a general
      "read the codebase" pass. Use targeted commands, e.g.:
      - npm/JS/TS: `grep -rn "from ['\"]ws['\"]" src/ app/` and
        `grep -rn "require(['\"]ws['\"])" src/ app/` — then open only the matching files to see
        how the import is actually used.
      - Java/Maven/Gradle: `grep -rn "import org.springframework" src/main/java/` — note
        `src/main` vs `src/test` explicitly (see prod-path rule below).
      - Python: `grep -rn "^import <pkg>\|^from <pkg>" --include=*.py .`
      - If ripgrep is available, prefer it (`rg`) for speed on large repos.

   d. **Determine if the usage is in a production code path, not just "used somewhere."** This is
      the distinction the user cares about most — a package can be genuinely called, but only from
      test code, build tooling, or a dev-only script that never ships. For each match found:
      - **Exclude** (mark not-prod-reachable) if the only usage is under: `test/`, `tests/`,
        `__tests__/`, `spec/`, `src/test/` (Java/Maven convention), files matching
        `*.test.*`/`*.spec.*`, `devDependencies`-only packages never imported from
        production-path files, build scripts (`webpack.config.js`, `gulpfile.js`,
        `build.gradle` buildscript blocks), or CI-only tooling.
      - **Include** (mark prod-reachable) if the usage is under production source directories
        (`src/main/java`, `src/`, `app/`, `lib/` outside a `dependencies`-vs-`devDependencies`
        distinction that excludes it) AND the package is not excluded from the final build
        artifact (verify: for Docker-shipped apps, confirm the file/module is actually copied into
        the production image/JAR/WAR — check the `Dockerfile`'s final stage or the
        packaging/assembly config, don't assume).
      - If genuinely uncertain after a targeted search, say so explicitly in
        `reachabilityEvidence` (e.g. "usage found only in src/test/java — confirm this test suite
        doesn't run against a live component embedded in prod") rather than guessing either way.

   e. **Record concrete evidence**, not a conclusion alone: exact `file:line`, the surrounding
      call, and which category it falls into (prod / test-only / build-only / not found at all).
      This evidence is what gets stored in `reachabilityEvidence` and is what a security reviewer
      would need to independently verify your triage without re-doing the search themselves.

   f. **Two distinct booleans, not one**, since they answer different questions:
      - `reachable` — is the vulnerable API called anywhere in the repo at all (including tests)?
      - `prodReachable` — is that call reachable in the artifact that actually ships/runs in
        production? **This is the field the disposition logic below should key off of** — a
        package reachable only in tests is a very different risk than one reachable in the
        deployed service.
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
5. **Assign disposition** using this priority order — based on `prodReachable`, not just
   `reachable`:
   - Not found in source at all (installed only, never imported/called anywhere) →
     `WAIVER_FALSE_POSITIVE`
   - `reachable = true` but `prodReachable = false` (only used in tests/build tooling/dev
     scripts, confirmed excluded from the shipped artifact) → `WAIVER_NOT_APPLICABLE` —
     state explicitly in the justification *why* it's excluded from prod (e.g. "only imported in
     `src/test/java`, and the test module is not packaged into the deployed JAR per
     `pom.xml`'s `<scope>test</scope>`").
   - `prodReachable = true`, but the specific exploit precondition doesn't hold in your deployment
     (e.g. requires a config flag you don't enable, or an input source you don't expose) →
     `WAIVER_NOT_APPLICABLE`, with the precondition explicitly named.
   - `prodReachable = true`, fix exists → `FIX_REQUIRED`
   - `prodReachable = true`, no fix, real exposure, no compensating control feasible right now →
     `ACCEPT_RISK_TEMPORARY` (must include compensating controls + review date)
   - `prodReachable = true`, no fix, exposure is significant/exploitable and no acceptable
     temporary control → `MUST_FIX_NO_PATCH` with alternative mitigation
   - **Never assign `FIX_REQUIRED` or any waiver based solely on `reachable` without having
     checked `prodReachable`** — a package used only in tests still technically satisfies
     `reachable = true`, but its risk profile is entirely different from production usage.
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

| Reference | Package | Version | Direct/Transitive | Used in Source? | Prod-Reachable? | Disposition | Fixed Version | Effort | Review By |
|---|---|---|---|---|---|---|---|---|---|

"Used in Source?" and "Prod-Reachable?" are deliberately separate columns — a package can be
`Yes` / `No` (used only in tests) just as easily as `Yes` / `Yes` (used in the shipped service).
Never collapse these into a single "reachable" column; that's exactly the ambiguity that led to
lockfile-only analysis in the first place.

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
