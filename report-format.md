# Report Format

## Summary table (always include, covers every item in the current run)

| Reference | Package | Version | Direct/Transitive | Used in Source? | Prod-Reachable? | Disposition | Fixed Version | Effort | Review By |
|---|---|---|---|---|---|---|---|---|---|

## Finding card (for every item that is NOT a trivial clean-bump FIX_REQUIRED)

Use this structure for anything non-trivial — `MUST_FIX_NO_PATCH`, `ACCEPT_RISK_TEMPORARY`, any
`WAIVER_*`, or a `FIX_REQUIRED` that involves an override/transitive pin rather than a simple
direct version bump:

```
### <Reference> — <package>@<current_version>

**What it is:** <plain-language CWE/CVE explanation — the mechanism, not just the label>

**Direct/Transitive:** <direct | transitive via <parent-chain>>

**Source evidence:**
- Used in source? <Yes/No> — <file:line or "no import/usage found">
- Prod-reachable? <Yes/No> — <reasoning: production source path & ships in build artifact,
  OR test/build-only and excluded from shipped artifact — name how you confirmed this>

**Disposition:** <FIX_REQUIRED | WAIVER_FALSE_POSITIVE | WAIVER_NOT_APPLICABLE |
ACCEPT_RISK_TEMPORARY | MUST_FIX_NO_PATCH>

**Justification:** <why this disposition, referencing the evidence above>

**Suggested fix:**
<concrete diff from remediation-patterns.md, using the actual file/syntax found in this repo —
not a generic example>

**Verify after applying:** <specific behavior to re-test>

**Review by:** <date, mandatory for ACCEPT_RISK_TEMPORARY and any WAIVER_*>
```

## Closing summary (always include)

- Count of findings per disposition.
- List of any findings whose `reviewBy` date has already passed — call these out separately as
  needing immediate re-triage, don't bury them in the table.
- List of any findings where reachability couldn't be conclusively determined (say so, don't
  force a guess into a clean Yes/No).

## Style rules

- Don't write a finding card for a straightforward `FIX_REQUIRED` clean patch-version bump with no
  ambiguity — one table row is enough. Reserve the narrative detail for cases that need judgment
  or a documented decision trail (waivers, risk acceptance, must-fix-no-patch, and any override
  that touches more than one consuming package).
- Every "Yes" under Prod-Reachable must have a citation (file:line); never state it as a bare
  conclusion.
- Keep the plain-language CVE explanation to 1–3 sentences — enough for a reviewer to understand
  the mechanism without re-reading the advisory, not a full restatement of it.
