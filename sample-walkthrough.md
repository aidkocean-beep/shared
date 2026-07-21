# Sample Walkthrough — End-to-End Run

This walks through a single real example (`CVE-2026-48779` in `ws@7.5.10`) from Sonatype export
through to the final report and cache state, plus what an incremental re-run looks like. Use this
as a reference for what "correct" output from this skill should look like.

---

## 1. Input

`vuln-reports/sonatype-export-2026-07-21.csv`:
```csv
package_ecosystem,package_name,current_version,reference
npm,ws,7.5.10,CVE-2026-48779
```

## 2. Prompt (Copilot Chat, agent mode)

```
Analyze vuln-reports/sonatype-export-2026-07-21.csv using the vulnerability-analyzer skill.
```

---

## 3. What the skill does internally

**Step 1–2 (cache diff):** No cache exists yet → this is a `NEW` finding, key
`CVE-2026-48779|npm|ws|7.5.10`.

**Step 3 — reachability** (loads `language-patterns.md`, npm section):
```
rg -n "from ['\"]ws['\"]" --type ts --type js
rg -n "require\(['\"]ws['\"]\)" --type ts --type js
```
Match found:
```
src/gateway/wsServer.ts:12:  import { WebSocketServer } from 'ws';
src/gateway/wsServer.ts:42:  const wss = new WebSocketServer({ port: config.wsPort });
```
`src/gateway/` is not under `test/`, `__tests__/`, or a config file — it's production source.
`npm ls --omit=dev` confirms `ws` is in the production dependency tree, not devDependencies-only.

→ `reachable: true`, `prodReachable: true`, evidence = `src/gateway/wsServer.ts:42`

**Step 4 — judge/verification pass:** Confirms the match is an actual `WebSocketServer`
construction (not an unrelated re-export from the same package). Confirms via the `Dockerfile`
that `src/gateway/` is copied into the final runtime image. Sets `verifiedByJudgePass: true`.

**Step 5 — remediation** (loads `remediation-patterns.md`): Direct dependency, patch fix exists
(`7.5.11`) → simple version-bump template selected.

---

## 4. Resulting report

### Summary table

| Reference | Package | Version | Direct/Transitive | Used in Source? | Prod-Reachable? | Disposition | Fixed Version | Effort | Review By |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-48779 | ws | 7.5.10 | Direct | Yes | Yes | FIX_REQUIRED | 7.5.11 | 🟢 Low | — |

This is a clean patch bump with no ambiguity, so per the report-format style rules it stays a
one-line table entry. The finding card below shows the fuller structure you'd get for anything
non-trivial (waivers, risk acceptance, must-fix-no-patch, or any override touching multiple
consumers) — included here for reference even though this particular case wouldn't normally
generate one.

### Finding card

```
### CVE-2026-48779 — ws@7.5.10

**What it is:** A peer can send a flood of exceptionally small WebSocket fragments, forcing
the server to allocate structural memory wrappers far exceeding the intended message-size
limit, eventually crashing the process from memory exhaustion (CWE-400/770, not RCE).

**Direct/Transitive:** Direct dependency.

**Source evidence:**
- Used in source? Yes — src/gateway/wsServer.ts:42, `new WebSocketServer({ port: config.wsPort })`
- Prod-reachable? Yes — src/gateway is included in the production Docker image
  (confirmed via Dockerfile COPY of src/gateway into the final runtime stage).

**Disposition:** FIX_REQUIRED

**Justification:** Direct, actively-instantiated WebSocket server in production code.
No mitigating factors; a clean patch-version fix exists.

**Suggested fix:**
```diff
--- a/package.json
+++ b/package.json
@@
   "dependencies": {
-    "ws": "7.5.10",
+    "ws": "7.5.11",
   }
```
Run `npm install && npm ls ws` afterward to confirm resolution.

**Verify after applying:** Smoke test WebSocket connect/message/disconnect/reconnect on
src/gateway/wsServer.ts — the fix only changes internal fragment-buffering limits, not the
public API, so no other behavior change is expected.

**Review by:** — (not applicable; this is a direct fix, not a waiver/risk-acceptance)
```

### Closing summary

```
1 finding analyzed | Disposition breakdown: FIX_REQUIRED: 1
No overdue reviews. No unresolved reachability.
```

---

## 5. Resulting `.copilot/vuln-cache.json`

```json
{
  "schemaVersion": 2,
  "findings": {
    "CVE-2026-48779|npm|ws|7.5.10": {
      "status": "ANALYZED",
      "reference": "CVE-2026-48779",
      "package": "ws",
      "ecosystem": "npm",
      "analyzedVersion": "7.5.10",
      "isDirect": true,
      "reachable": true,
      "prodReachable": true,
      "reachabilityEvidence": [
        "src/gateway/wsServer.ts:42 — new WebSocketServer(...) — ships in prod Docker image"
      ],
      "disposition": "FIX_REQUIRED",
      "fixedVersion": "7.5.11",
      "suggestedDiff": "package.json: \"ws\": \"7.5.10\" -> \"7.5.11\"",
      "isBreakingChange": false,
      "effort": "LOW",
      "justification": "Direct WebSocket server usage confirmed at wsServer.ts:42; clean patch bump.",
      "reviewBy": null,
      "verifiedByJudgePass": true,
      "codeFilesChecked": ["src/gateway/wsServer.ts"],
      "codeFilesHash": "sha256:9f2a..."
    }
  }
}
```

---

## 6. Next run — what "incremental" looks like in practice

Scenario: next week's Sonatype export still lists `CVE-2026-48779` with `ws` still at `7.5.10`
(the fix hasn't been merged yet), and adds one new finding for a Java dependency.

- **`ws@7.5.10` finding** — cache key unchanged, `wsServer.ts` hash unchanged →
  **pulled straight from cache**. Zero re-analysis, zero source re-reads, zero tokens spent
  re-deriving the CVE explanation, reachability, or the diff.
- **New Java finding** — only this one goes through Steps 3–5.

Once the `ws` bump is actually merged and the next Sonatype export reflects `ws@7.5.11` (or the
finding disappears from the scan entirely because it's fixed), the old `7.5.10` cache key no
longer matches anything in the input list — so a stale cache can't misreport a resolved
vulnerability as still open. The old entry stays in the cache as historical record
(`status: "OUT_OF_SCOPE"` if explicitly pruned, or simply excluded from future reports if the key
just stops appearing in new exports).
